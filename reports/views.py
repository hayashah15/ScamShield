from datetime import timedelta
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User
from django.core.paginator import Paginator
from django.db.models import Count, F, Q, Sum
from django.db.models.functions import TruncDate
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.html import escape
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_POST
from django.views.generic import CreateView, DeleteView, DetailView, UpdateView

from . import detection, services
from .forms import AnalyzeForm, CommentForm, ReportForm, SearchFilterForm
from .models import Evidence, Report, ScamType, SearchLog, Vote

RECENT_SEARCH_LIMIT = 8


# --------------------------------------------------------------------------- #
#  Session helpers (recent searches, recently viewed, already-voted)
# --------------------------------------------------------------------------- #
def remember_search(request, query, kind):
    recent = [s for s in request.session.get('recent_searches', []) if s['q'].lower() != query.lower()]
    recent.insert(0, {'q': query, 'kind': kind})
    request.session['recent_searches'] = recent[:RECENT_SEARCH_LIMIT]


def remember_view(request, report_id):
    viewed = request.session.get('recently_viewed', [])
    first_time = report_id not in viewed
    viewed = [report_id] + [v for v in viewed if v != report_id]
    request.session['recently_viewed'] = viewed[:6]
    return first_time


# --------------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------------- #
def home(request):
    recent = Report.objects.visible().with_votes().select_related('scam_type')[:6]
    types = ScamType.objects.annotate(n=Count('reports', filter=Q(reports__is_hidden=False))).order_by('-n')
    week_ago = timezone.now() - timedelta(days=7)
    trending = (SearchLog.objects.filter(created_at__gte=week_ago, result_count__gt=0)
                .values('normalized', 'kind').annotate(n=Count('id')).order_by('-n')[:5])
    trending = [{**t, 'label': detection.pretty_phone(t['normalized']) if t['kind'] == 'phone' else t['normalized']}
                for t in trending]
    viewed_ids = request.session.get('recently_viewed', [])
    viewed = sorted(Report.objects.visible().filter(pk__in=viewed_ids), key=lambda r: viewed_ids.index(r.pk))
    return render(request, 'reports/home.html', {
        'recent': recent, 'types': types, 'trending': trending,
        'totals': services.site_totals(), 'viewed': viewed[:4],
    })


def search(request):
    form = SearchFilterForm(request.GET or None)
    form.is_valid()
    data = getattr(form, 'cleaned_data', {}) or {}
    q = (data.get('q') or '').strip()
    result = None
    if q:
        result = services.lookup(q)
        remember_search(request, q, result.kind)
        reports = result.exact + result.related
    else:
        reports = list(Report.objects.visible().with_votes().select_related('scam_type'))

    if data.get('type'):
        reports = [r for r in reports if r.scam_type_id == data['type'].id]
    if data.get('status'):
        reports = [r for r in reports if r.status == data['status']]
    sort = data.get('sort') or ''
    if sort == 'votes':
        reports.sort(key=lambda r: r.scam_votes, reverse=True)
    elif sort == 'views':
        reports.sort(key=lambda r: r.view_count, reverse=True)
    elif sort == 'loss':
        reports.sort(key=lambda r: r.amount_lost, reverse=True)
    elif sort == 'recent' or not q:
        reports.sort(key=lambda r: r.created_at, reverse=True)

    exact_ids = {r.pk for r in result.exact} if result else set()
    page = Paginator(reports, 10).get_page(request.GET.get('page'))
    params = request.GET.copy()
    params.pop('page', None)
    return render(request, 'reports/search.html', {
        'form': form, 'q': q, 'result': result, 'page': page, 'exact_ids': exact_ids,
        'querystring': params.urlencode(), 'total': len(reports),
    })


class ReportDetailView(DetailView):
    model = Report
    template_name = 'reports/report_detail.html'
    context_object_name = 'report'

    def get_queryset(self):
        qs = Report.objects.with_votes().select_related('scam_type', 'author__profile')
        if not (self.request.user.is_staff):
            qs = qs.filter(Q(is_hidden=False) | Q(author_id=self.request.user.pk or 0))
        return qs

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        if remember_view(request, self.object.pk):
            Report.objects.filter(pk=self.object.pk).update(view_count=F('view_count') + 1)
        return response

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        r, user = self.object, self.request.user
        my_vote = None
        if user.is_authenticated:
            my_vote = r.votes.filter(user=user).values_list('is_scam', flat=True).first()
        else:
            my_vote = self.request.session.get('voted', {}).get(str(r.pk))
        siblings = (Report.objects.visible().with_votes().filter(normalized_identifier=r.normalized_identifier)
                    .exclude(pk=r.pk))
        similar = (Report.objects.visible().with_votes().filter(scam_type=r.scam_type).exclude(pk=r.pk)
                   .exclude(pk__in=siblings.values('pk'))[:4])
        analysis = detection.analyze_message(r.description)
        ctx.update({
            'my_vote': my_vote, 'comment_form': CommentForm(),
            'comments': r.comments.select_related('author__profile'),
            'siblings': siblings, 'similar': similar, 'signals': detection.inspect_identifier(r.identifier, r.identifier_type),
            'highlighted': highlight(analysis), 'analysis': analysis,
            'targeted_count': r.comments.filter(also_targeted=True).count(),
            'can_edit': user.is_authenticated and (user == r.author or user.is_staff),
            'share_url': self.request.build_absolute_uri(r.get_absolute_url()),
        })
        return ctx


class ReportCreateView(LoginRequiredMixin, CreateView):
    model = Report
    form_class = ReportForm
    template_name = 'reports/report_form.html'

    def get_initial(self):
        initial = super().get_initial()
        if self.request.GET.get('identifier'):
            initial['identifier'] = self.request.GET['identifier'][:255]
        if self.request.GET.get('description'):
            initial['description'] = self.request.GET['description'][:3000]
        return initial

    def form_valid(self, form):
        form.instance.author = self.request.user
        form.instance.identifier_type = form.cleaned_data['identifier_type']
        response = super().form_valid(form)
        for f in form.cleaned_data.get('evidence', []):
            Evidence.objects.create(report=self.object, image=f)
        self.request.user.profile.recalculate()
        dupes = self.object.same_identifier_count - 1
        msg = 'Thank you! Your report is live and the community can now verify it.'
        if dupes:
            msg += f' {dupes} other report{"s" if dupes > 1 else ""} already mention this contact.'
        messages.success(self.request, msg)
        return response


class AuthorOrStaffMixin(UserPassesTestMixin):
    def test_func(self):
        obj = self.get_object()
        return self.request.user.is_staff or obj.author == self.request.user


class ReportUpdateView(LoginRequiredMixin, AuthorOrStaffMixin, UpdateView):
    model = Report
    form_class = ReportForm
    template_name = 'reports/report_form.html'

    def form_valid(self, form):
        form.instance.identifier_type = form.cleaned_data['identifier_type']
        response = super().form_valid(form)
        for f in form.cleaned_data.get('evidence', []):
            Evidence.objects.create(report=self.object, image=f)
        messages.success(self.request, 'Report updated.')
        return response


class ReportDeleteView(LoginRequiredMixin, AuthorOrStaffMixin, DeleteView):
    model = Report
    template_name = 'reports/report_confirm_delete.html'
    success_url = reverse_lazy('dashboard')

    def form_valid(self, form):
        author = self.get_object().author
        response = super().form_valid(form)
        author.profile.recalculate()
        messages.info(self.request, 'Report deleted.')
        return response


@login_required
@require_POST
def vote(request, pk):
    report = get_object_or_404(Report.objects.visible(), pk=pk)
    choice = request.POST.get('choice')
    if choice not in ('scam', 'safe', 'clear'):
        return JsonResponse({'error': 'Invalid choice'}, status=400)
    ajax = request.headers.get('x-requested-with') == 'XMLHttpRequest'
    if report.author == request.user:
        msg = 'You cannot vote on your own report.'
        if ajax:
            return JsonResponse({'error': msg}, status=403)
        messages.warning(request, msg)
        return redirect(report)

    voted = request.session.get('voted', {})
    if choice == 'clear':
        Vote.objects.filter(report=report, user=request.user).delete()
        voted.pop(str(pk), None)
    else:
        Vote.objects.update_or_create(report=report, user=request.user, defaults={'is_scam': choice == 'scam'})
        voted[str(pk)] = choice == 'scam'
    request.session['voted'] = voted
    old_status = report.status
    report.recompute_status()
    request.user.profile.recalculate()

    payload = {'scam': report.votes.filter(is_scam=True).count(), 'safe': report.votes.filter(is_scam=False).count(),
               'status': report.status, 'status_label': report.get_status_display(),
               'status_changed': old_status != report.status,
               'my_vote': None if choice == 'clear' else choice}
    payload['confidence'] = round(100 * (payload['scam'] + 1) / (payload['scam'] + payload['safe'] + 1))
    if ajax:
        return JsonResponse(payload)
    if payload['status_changed']:
        messages.success(request, f'Thanks to your vote this report is now "{report.get_status_display()}".')
    else:
        messages.success(request, 'Vote recorded.')
    return redirect(report)


@login_required
@require_POST
def add_comment(request, pk):
    report = get_object_or_404(Report.objects.visible(), pk=pk)
    form = CommentForm(request.POST)
    if form.is_valid():
        c = form.save(commit=False)
        c.report, c.author = report, request.user
        c.save()
        request.user.profile.recalculate()
        messages.success(request, 'Comment posted.')
    else:
        messages.error(request, 'Your comment could not be posted: ' + '; '.join(form.errors.get('body', [])))
    return redirect(report.get_absolute_url() + '#comments')


def highlight(analysis):
    """Return the message as HTML with red-flag phrases wrapped in <mark>."""
    text, out, pos = analysis.text, [], 0
    for start, end, cat in analysis.spans:
        out.append(escape(text[pos:start]))
        out.append(f'<mark class="flag" data-cat="{escape(cat)}" title="{escape(cat)}">{escape(text[start:end])}</mark>')
        pos = end
    out.append(escape(text[pos:]))
    return mark_safe(''.join(out))


SAMPLES = {
    'job': "Hi! We came across your resume on Indeed. Our company is hiring remote data entry assistants, $45/hr, "
           "no experience needed. Interview will be on Telegram. Before starting you must pay a $200 training kit "
           "fee by e-transfer. Reply within 24 hours to secure your spot! Contact hr.recruit.team@gmail.com",
    'cra': "CRA NOTICE: Your SIN has been suspended due to suspicious activity. A warrant will be issued for your "
           "arrest unless you pay the outstanding balance immediately using Google Play gift cards. Call (876) 555-0199 now. "
           "Do not tell anyone about this case.",
    'rental': "Beautiful 2BR near campus, $950/month all inclusive! I am currently out of the country for work so "
              "I can't show the unit, but I will send the keys by courier once you send the deposit by e-transfer. "
              "Pictures at rent-deals-toronto.xyz",
    'bank': "Dear customer, your account has been locked. Verify your identity within 24 hours to avoid suspension: "
            "http://rbc-secure-login.top/verify Enter your card number and one-time code.",
}


def analyze(request):
    form = AnalyzeForm(request.POST or None)
    if request.method == 'GET' and request.GET.get('sample') in SAMPLES:
        form = AnalyzeForm({'message': SAMPLES[request.GET['sample']]})
    ctx = {'form': form, 'samples': SAMPLES}
    if form.is_bound and form.is_valid():
        a = detection.analyze_message(form.cleaned_data['message'])
        linked = []
        for kind, raw, norm in a.identifiers:
            res = services.lookup(raw, log=False)
            linked.append({'kind': kind, 'raw': raw, 'norm': norm, 'result': res})
            if res.exact:   # community data outranks heuristics
                a.score = min(100, max(a.score, res.score))
        ctx.update({'analysis': a, 'highlighted': highlight(a), 'linked': linked,
                    'verdict': detection.verdict_for(a.score) if not any(l['result'].exact for l in linked)
                    else ('Linked to reported scam', 'danger')})
    return render(request, 'reports/analyze.html', ctx)


def dashboard(request):
    visible = Report.objects.visible()
    now = timezone.now()
    start = (now - timedelta(days=29)).date()
    daily = dict(visible.filter(created_at__date__gte=start).annotate(d=TruncDate('created_at'))
                 .values_list('d').annotate(n=Count('id')).values_list('d', 'n'))
    days = [start + timedelta(days=i) for i in range(30)]
    series = [daily.get(d, 0) for d in days]
    peak = max(series) or 1
    timeline = [{'date': d, 'n': n, 'h': round(100 * n / peak)} for d, n in zip(days, series)]

    by_type = list(ScamType.objects.annotate(
        n=Count('reports', filter=Q(reports__is_hidden=False)),
        lost=Sum('reports__amount_lost', filter=Q(reports__is_hidden=False))).filter(n__gt=0).order_by('-n'))
    top_n = by_type[0].n if by_type else 1
    for t in by_type:
        t.pct = round(100 * t.n / top_n)

    status_counts = {s: visible.filter(status=s).count() for s in ('confirmed', 'suspected', 'disputed')}
    total = sum(status_counts.values()) or 1
    c_end = 100 * status_counts['confirmed'] / total
    s_end = c_end + 100 * status_counts['suspected'] / total
    channels = (visible.values('channel').annotate(n=Count('id')).order_by('-n'))
    channel_labels = dict(Report.Channel.choices)
    channels = [{'label': channel_labels.get(c['channel'], c['channel']), 'n': c['n'],
                 'pct': round(100 * c['n'] / total)} for c in channels]

    top_identifiers = (visible.values('normalized_identifier', 'identifier_type')
                       .annotate(n=Count('id'), lost=Sum('amount_lost')).filter(n__gt=1).order_by('-n')[:6])
    top_identifiers = [{**t, 'label': detection.pretty_phone(t['normalized_identifier'])
                        if t['identifier_type'] == 'phone' else t['normalized_identifier']} for t in top_identifiers]
    leaders = User.objects.select_related('profile').filter(profile__reputation__gt=0).order_by('-profile__reputation')[:6]

    mine = None
    if request.user.is_authenticated:
        mine = request.user.reports.with_votes().select_related('scam_type')
    return render(request, 'reports/dashboard.html', {
        'totals': services.site_totals(), 'timeline': timeline, 'by_type': by_type,
        'status_counts': status_counts, 'c_end': c_end, 's_end': s_end, 'channels': channels,
        'top_identifiers': top_identifiers, 'leaders': leaders, 'mine': mine,
        'last30': sum(series),
    })


def scam_type_detail(request, slug):
    st = get_object_or_404(ScamType, slug=slug)
    reports = st.reports.visible().with_votes()
    agg = reports.aggregate(lost=Sum('amount_lost'))
    page = Paginator(reports, 8).get_page(request.GET.get('page'))
    return render(request, 'reports/scam_type.html', {'type': st, 'page': page, 'lost': agg['lost'] or 0,
                                                      'count': reports.count()})


@require_POST
def clear_history(request):
    for key in ('recent_searches', 'recently_viewed'):
        request.session.pop(key, None)
    messages.info(request, 'Your search history on this device was cleared.')
    return redirect(request.POST.get('next') or 'home')


# --------------------------------------------------------------------------- #
#  JSON API (live check-as-you-type, usable by a browser extension later)
# --------------------------------------------------------------------------- #
def api_check(request):
    q = request.GET.get('q', '').strip()
    if len(q) < 4:
        return JsonResponse({'query': q, 'ready': False})
    res = services.lookup(q, log=request.GET.get('log') == '1')
    label, tone = res.verdict
    return JsonResponse({
        'ready': True, 'query': q, 'type': res.kind, 'normalized': res.normalized,
        'score': res.score, 'verdict': label, 'tone': tone, 'headline': res.headline,
        'reports': [{'id': r.pk, 'title': r.title, 'status': r.status, 'type': r.scam_type.name,
                     'votes': r.scam_votes, 'url': request.build_absolute_uri(r.get_absolute_url())}
                    for r in res.exact[:5]],
        'related_count': len(res.related),
        'signals': [{'label': s.label, 'detail': s.detail, 'level': s.level} for s in res.signals if s.weight or s.level != 'info'],
        'search_url': reverse('search') + '?' + urlencode({'q': q}),
    })
