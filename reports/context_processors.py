from .models import ScamType


def site_context(request):
    return {
        'nav_types': ScamType.objects.all(),
        'recent_searches': request.session.get('recent_searches', []),
        'visit_count': getattr(request, 'visit_count', 1),
    }
