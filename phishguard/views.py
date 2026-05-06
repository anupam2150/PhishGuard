from django.shortcuts import render


def ratelimited_error(request, exception):
    """
    Called by django-ratelimit when a rate limit is exceeded (block=True).
    Renders the 429 template with context about which limit was hit.
    """
    rate = getattr(exception, "rate", None) or ""
    window_map = {"s": "second", "m": "minute", "h": "hour", "d": "day"}
    retry_map  = {"s": 1, "m": 1, "h": 60, "d": 1440}
    limit_num    = ""
    window_label = "hour"
    retry_mins   = 60
    if "/" in rate:
        num, period = rate.split("/", 1)
        limit_num    = num
        period_char  = period[-1].lower() if period else "h"
        window_label = window_map.get(period_char, "hour")
        retry_mins   = retry_map.get(period_char, 60)
    return render(request, "429.html", {
        "rate":         rate,
        "limit_num":    limit_num,
        "window_label": window_label,
        "retry_mins":   retry_mins,
    }, status=429)


def custom_404(request, exception=None):
    return render(request, "404.html", status=404)


def custom_500(request):
    return render(request, "500.html", status=500)
