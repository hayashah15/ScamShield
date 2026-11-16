from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.db.models import Count, Q
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify

from . import detection


class ScamType(models.Model):
    name = models.CharField(max_length=60, unique=True)
    slug = models.SlugField(max_length=70, unique=True, blank=True)
    icon = models.CharField(max_length=8, default='⚠️', help_text='An emoji shown next to the type')
    description = models.CharField(max_length=240, blank=True)
    how_to_spot = models.TextField(blank=True, help_text='One tip per line')

    class Meta:
        ordering = ['name']

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    def tips(self):
        return [t.strip() for t in self.how_to_spot.splitlines() if t.strip()]

    def __str__(self):
        return self.name


class ReportQuerySet(models.QuerySet):
    def visible(self):
        return self.filter(is_hidden=False)

    def with_votes(self):
        return self.annotate(
            scam_count=Count('votes', filter=Q(votes__is_scam=True), distinct=True),
            safe_count=Count('votes', filter=Q(votes__is_scam=False), distinct=True),
        ).order_by('-created_at')   # Meta.ordering is ignored on GROUP BY queries


class Report(models.Model):
    class IdentifierType(models.TextChoices):
        PHONE = 'phone', 'Phone number'
        URL = 'url', 'Website'
        EMAIL = 'email', 'Email address'
        NAME = 'name', 'Person / business name'

    class Status(models.TextChoices):
        SUSPECTED = 'suspected', 'Suspected'
        CONFIRMED = 'confirmed', 'Confirmed'
        DISPUTED = 'disputed', 'Disputed'

    class Channel(models.TextChoices):
        TEXT = 'text', 'Text / SMS'
        CALL = 'call', 'Phone call'
        EMAIL = 'email', 'Email'
        SOCIAL = 'social', 'Social media / marketplace'
        WEBSITE = 'website', 'Website'
        PERSON = 'person', 'In person'

    title = models.CharField(max_length=120)
    description = models.TextField()
    identifier = models.CharField(max_length=255, help_text='Phone number, website, email or name')
    identifier_type = models.CharField(max_length=10, choices=IdentifierType.choices, blank=True)
    normalized_identifier = models.CharField(max_length=255, db_index=True, editable=False)
    scam_type = models.ForeignKey(ScamType, on_delete=models.PROTECT, related_name='reports')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    channel = models.CharField(max_length=10, choices=Channel.choices, default=Channel.TEXT)
    amount_lost = models.DecimalField(max_digits=10, decimal_places=2, default=0,
                                      help_text='Leave at 0 if you did not lose money')
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.SUSPECTED, db_index=True)
    status_locked = models.BooleanField(default=False, help_text='Moderator override: votes no longer change status')
    is_hidden = models.BooleanField(default=False, help_text='Removed by a moderator')
    view_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ReportQuerySet.as_manager()

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.identifier_type:
            self.identifier_type = detection.detect_type(self.identifier)
        self.normalized_identifier = detection.normalize(self.identifier, self.identifier_type)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse('report_detail', args=[self.pk])

    def __str__(self):
        return self.title

    # --- votes ---------------------------------------------------------------
    @property
    def scam_votes(self):
        if hasattr(self, 'scam_count'):
            return self.scam_count
        return self.votes.filter(is_scam=True).count()

    @property
    def safe_votes(self):
        if hasattr(self, 'safe_count'):
            return self.safe_count
        return self.votes.filter(is_scam=False).count()

    @property
    def total_votes(self):
        return (self.scam_votes or 0) + (self.safe_votes or 0)

    @property
    def confidence(self):
        """Percent of voters who say it is a scam (author counts as one implicit scam vote)."""
        scam, safe = (self.scam_votes or 0) + 1, self.safe_votes or 0
        return round(100 * scam / (scam + safe))

    def recompute_status(self, save=True):
        """Community verification: Suspected -> Confirmed / Disputed based on votes."""
        if self.status_locked:
            return self.status
        rules = settings.SCAMSHIELD
        scam = self.votes.filter(is_scam=True).count()
        safe = self.votes.filter(is_scam=False).count()
        total = scam + safe
        new = self.Status.SUSPECTED
        if total and scam >= rules['CONFIRM_MIN_VOTES'] and scam / total >= rules['CONFIRM_RATIO']:
            new = self.Status.CONFIRMED
        elif total >= 2 and safe / total >= rules['DISPUTE_RATIO']:
            new = self.Status.DISPUTED
        if new != self.status:
            self.status = new
            if save:
                Report.objects.filter(pk=self.pk).update(status=new)
            if hasattr(self.author, 'profile'):
                self.author.profile.recalculate()
        return self.status

    @property
    def display_identifier(self):
        if self.identifier_type == 'phone':
            return detection.pretty_phone(self.normalized_identifier)
        return self.identifier

    @property
    def same_identifier_count(self):
        return Report.objects.visible().filter(normalized_identifier=self.normalized_identifier).count()


def evidence_path(instance, filename):
    return f'evidence/{timezone.now():%Y/%m}/{filename}'


class Evidence(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='evidence')
    image = models.ImageField(upload_to=evidence_path)
    caption = models.CharField(max_length=140, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['uploaded_at']
        verbose_name_plural = 'evidence'

    def __str__(self):
        return f'Evidence for #{self.report_id}'


class Vote(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='votes')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='votes')
    is_scam = models.BooleanField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['report', 'user'], name='one_vote_per_user_per_report')]

    def __str__(self):
        return f'{self.user} → {"scam" if self.is_scam else "not scam"} on #{self.report_id}'


class Comment(models.Model):
    report = models.ForeignKey(Report, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    body = models.TextField(max_length=1000)
    also_targeted = models.BooleanField(default=False, help_text='"This happened to me too"')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'Comment by {self.author} on #{self.report_id}'


class SearchLog(models.Model):
    """Anonymous lookup log: powers 'trending lookups' and the 'checked N times' counter."""
    query = models.CharField(max_length=255)
    normalized = models.CharField(max_length=255, db_index=True)
    kind = models.CharField(max_length=10)
    result_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.query
