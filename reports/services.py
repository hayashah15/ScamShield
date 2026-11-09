"""Search + risk scoring shared by the HTML views and the JSON API."""
from dataclasses import dataclass, field

from django.db.models import Q, Sum

from . import detection
from .models import Report, SearchLog


@dataclass
class Lookup:
    query: str
    kind: str
    normalized: str
    exact: list = field(default_factory=list)
    related: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    score: int = 0
    lookups: int = 0
    total_lost: float = 0

    @property
    def verdict(self):
        if self.exact and any(r.status == 'confirmed' for r in self.exact):
            return ('Confirmed scam', 'danger')
        if not self.exact and self.score < 15:
            return ('No reports yet', 'good')
        return detection.verdict_for(self.score)

    @property
    def headline(self):
        n = len(self.exact)
        if n:
            people = sum(1 + r.scam_votes for r in self.exact)
            return f'Reported {n} time{"s" if n != 1 else ""}, flagged by {people} people'
        if self.score >= 40:
            return 'No community reports, but the address itself shows warning signs'
        return 'No one has reported this yet. That is not a guarantee it is safe.'


def risk_score(exact_reports, signals):
    score = 0
    if exact_reports:
        score += 45 + 8 * min(len(exact_reports) - 1, 3)
        for r in exact_reports:
            if r.status == 'confirmed':
                score += 25
                break
        votes_scam = sum(r.scam_votes for r in exact_reports)
        votes_safe = sum(r.safe_votes for r in exact_reports)
        score += min(votes_scam * 2, 15) - votes_safe * 6
        if all(r.status == 'disputed' for r in exact_reports):
            score = min(score, 30)
    heur = sum(s.weight for s in signals)
    score += heur if not exact_reports else heur // 2
    if not exact_reports:
        score = min(score, 85)  # heuristics alone never claim certainty
    return max(0, min(100, score))


def lookup(query: str, log=True) -> Lookup:
    query = (query or '').strip()[:255]
    kind = detection.detect_type(query)
    norm = detection.normalize(query, kind)
    res = Lookup(query=query, kind=kind, normalized=norm)
    if not norm:
        return res

    base = Report.objects.visible().with_votes().select_related('scam_type', 'author')
    match = Q(normalized_identifier=norm)
    if kind == 'email':
        dom = detection.domain_of(query)
        if dom not in detection.FREE_MAIL:
            match |= Q(normalized_identifier=dom)         # email on a reported scam domain
    if kind == 'url':
        match |= Q(normalized_identifier__endswith='@' + norm)  # emails sent from this domain
    res.exact = list(base.filter(match))

    text = (Q(title__icontains=query) | Q(description__icontains=query) |
            Q(identifier__icontains=query) | Q(normalized_identifier__icontains=norm))
    if kind == 'phone' and len(norm) == 10:
        text |= Q(description__icontains=detection.pretty_phone(norm)) | Q(description__icontains=norm)
    res.related = list(base.filter(text).exclude(pk__in=[r.pk for r in res.exact])[:12])

    res.signals = detection.inspect_identifier(query, kind) if kind != 'name' else []
    res.score = risk_score(res.exact, res.signals)
    res.total_lost = sum(float(r.amount_lost) for r in res.exact)
    res.lookups = SearchLog.objects.filter(normalized=norm).count()
    if log:
        SearchLog.objects.create(query=query, normalized=norm, kind=kind,
                                 result_count=len(res.exact) + len(res.related))
        res.lookups += 1
    return res


def site_totals():
    visible = Report.objects.visible()
    return {
        'reports': visible.count(),
        'confirmed': visible.filter(status='confirmed').count(),
        'lost': visible.aggregate(s=Sum('amount_lost'))['s'] or 0,
        'lookups': SearchLog.objects.count(),
    }
