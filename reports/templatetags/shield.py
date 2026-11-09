from django import template

from reports import detection

register = template.Library()

STATUS_TONE = {'confirmed': 'danger', 'suspected': 'warn', 'disputed': 'muted'}
KIND_ICON = {'phone': '📞', 'url': '🌐', 'email': '✉️', 'name': '👤'}


@register.filter
def status_tone(status):
    return STATUS_TONE.get(status, 'muted')


@register.filter
def kind_icon(kind):
    return KIND_ICON.get(kind, '🔎')


@register.filter
def pretty_phone(value):
    return detection.pretty_phone(value)


@register.filter
def initials(user):
    name = user.get_full_name() or user.username
    parts = name.replace('_', ' ').replace('.', ' ').split()
    return ''.join(p[0] for p in parts[:2]).upper() or '?'


@register.simple_tag
def gauge_dash(score, length=251.2):
    """stroke-dasharray for a semicircle gauge of path length ~251 (r=80)."""
    filled = length * max(0, min(100, int(score))) / 100
    return f'{filled:.1f} {length:.1f}'


@register.simple_tag(takes_context=True)
def url_replace(context, **kwargs):
    query = context['request'].GET.copy()
    for k, v in kwargs.items():
        query[k] = v
    return query.urlencode()
