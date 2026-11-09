from django.utils import timezone

VISITS_COOKIE = 'ss_visits'
LAST_COOKIE = 'ss_last_visit'
ONE_YEAR = 60 * 60 * 24 * 365


class VisitCounterMiddleware:
    """Counts visits (one per calendar day) in cookies, so returning users get a 'welcome back'."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        today = timezone.localdate().isoformat()
        try:
            visits = int(request.COOKIES.get(VISITS_COOKIE, 0))
        except ValueError:
            visits = 0
        new_day = request.COOKIES.get(LAST_COOKIE) != today
        if new_day:
            visits += 1
        request.visit_count = max(visits, 1)
        request.is_returning = visits > 1
        response = self.get_response(request)
        if new_day and not request.path.startswith(('/static/', '/media/', '/api/')):
            response.set_cookie(VISITS_COOKIE, str(request.visit_count), max_age=ONE_YEAR, samesite='Lax')
            response.set_cookie(LAST_COOKIE, today, max_age=ONE_YEAR, samesite='Lax')
        return response
