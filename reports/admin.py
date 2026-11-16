from django.contrib import admin, messages
from django.db.models import Count, Q
from django.utils.html import format_html

from .models import Comment, Evidence, Report, ScamType, SearchLog, Vote


class EvidenceInline(admin.TabularInline):
    model = Evidence
    extra = 0
    readonly_fields = ['preview', 'uploaded_at']
    fields = ['preview', 'image', 'caption', 'uploaded_at']

    @admin.display(description='Preview')
    def preview(self, obj):
        if obj.image:
            return format_html('<a href="{}" target="_blank"><img src="{}" style="height:90px;border-radius:6px"></a>',
                               obj.image.url, obj.image.url)
        return '—'


class VoteInline(admin.TabularInline):
    model = Vote
    extra = 0
    readonly_fields = ['user', 'is_scam', 'created_at']
    can_delete = True


class CommentInline(admin.StackedInline):
    model = Comment
    extra = 0
    readonly_fields = ['author', 'created_at']


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'title', 'identifier', 'scam_type', 'status_badge', 'scam_votes_col', 'safe_votes_col',
                    'amount_lost', 'author', 'created_at', 'is_hidden']
    list_display_links = ['id', 'title']
    list_filter = ['status', 'is_hidden', 'scam_type', 'identifier_type', 'channel', 'status_locked', 'created_at']
    search_fields = ['title', 'description', 'identifier', 'normalized_identifier', 'author__username']
    readonly_fields = ['normalized_identifier', 'view_count', 'updated_at']
    date_hierarchy = 'created_at'
    inlines = [EvidenceInline, VoteInline, CommentInline]
    actions = ['mark_confirmed', 'mark_suspected', 'mark_disputed', 'hide_reports', 'restore_reports', 'unlock_status']
    list_per_page = 25
    fieldsets = [
        (None, {'fields': ['title', 'description', 'scam_type', 'channel', 'amount_lost', 'author']}),
        ('Contact', {'fields': ['identifier', 'identifier_type', 'normalized_identifier']}),
        ('Moderation', {'fields': ['status', 'status_locked', 'is_hidden', 'view_count', 'created_at', 'updated_at']}),
    ]

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(
            _scam=Count('votes', filter=Q(votes__is_scam=True)), _safe=Count('votes', filter=Q(votes__is_scam=False)))

    @admin.display(description='Status', ordering='status')
    def status_badge(self, obj):
        colors = {'confirmed': '#E4572E', 'suspected': '#F2A93B', 'disputed': '#5B6B7C'}
        lock = ' 🔒' if obj.status_locked else ''
        return format_html('<span style="background:{};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px">{}</span>{}',
                           colors.get(obj.status, '#999'), obj.get_status_display(), lock)

    @admin.display(description='👎 Scam', ordering='_scam')
    def scam_votes_col(self, obj):
        return obj._scam

    @admin.display(description='👍 Safe', ordering='_safe')
    def safe_votes_col(self, obj):
        return obj._safe

    def _set_status(self, request, queryset, status):
        n = queryset.update(status=status, status_locked=True)
        for r in queryset.select_related('author__profile'):
            r.author.profile.recalculate()
        self.message_user(request, f'{n} report(s) marked {status} and locked.', messages.SUCCESS)

    @admin.action(description='✅ Approve as Confirmed (lock)')
    def mark_confirmed(self, request, queryset):
        self._set_status(request, queryset, 'confirmed')

    @admin.action(description='Mark as Suspected (lock)')
    def mark_suspected(self, request, queryset):
        self._set_status(request, queryset, 'suspected')

    @admin.action(description='Mark as Disputed (lock)')
    def mark_disputed(self, request, queryset):
        self._set_status(request, queryset, 'disputed')

    @admin.action(description='🚫 Remove from public site')
    def hide_reports(self, request, queryset):
        self.message_user(request, f'{queryset.update(is_hidden=True)} report(s) hidden.', messages.WARNING)

    @admin.action(description='Restore to public site')
    def restore_reports(self, request, queryset):
        self.message_user(request, f'{queryset.update(is_hidden=False)} report(s) restored.')

    @admin.action(description='🔓 Unlock: let community votes decide again')
    def unlock_status(self, request, queryset):
        queryset.update(status_locked=False)
        for r in queryset:
            r.recompute_status()
        self.message_user(request, 'Status unlocked and recalculated from votes.')


@admin.register(ScamType)
class ScamTypeAdmin(admin.ModelAdmin):
    list_display = ['icon', 'name', 'slug', 'report_count']
    prepopulated_fields = {'slug': ['name']}
    list_display_links = ['name']

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(_n=Count('reports'))

    @admin.display(description='Reports', ordering='_n')
    def report_count(self, obj):
        return obj._n


@admin.register(Vote)
class VoteAdmin(admin.ModelAdmin):
    list_display = ['report', 'user', 'is_scam', 'created_at']
    list_filter = ['is_scam']
    search_fields = ['report__title', 'user__username']


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ['report', 'author', 'short', 'also_targeted', 'created_at']
    list_filter = ['also_targeted']
    search_fields = ['body', 'author__username']

    @admin.display(description='Comment')
    def short(self, obj):
        return obj.body[:80]


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ['report', 'caption', 'uploaded_at']


@admin.register(SearchLog)
class SearchLogAdmin(admin.ModelAdmin):
    list_display = ['query', 'kind', 'result_count', 'created_at']
    list_filter = ['kind']
    search_fields = ['query', 'normalized']
