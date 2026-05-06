def sidebar_counts(request):
    counts = {"scanner": 0, "email": 0, "intel": 0, "ssl": 0, "redirect": 0, "emailcheck": 0, "watchlist_alerts": 0}
    try:
        from scanner.models import ScanResult
        counts["scanner"] = ScanResult.objects.count()
    except Exception:
        pass
    try:
        from emailparser.models import EmailScan
        counts["email"] = EmailScan.objects.count()
    except Exception:
        pass
    try:
        from intel.models import ThreatReport
        counts["intel"] = ThreatReport.objects.count()
    except Exception:
        pass
    try:
        from sslchecker.models import SSLReport
        counts["ssl"] = SSLReport.objects.count()
    except Exception:
        pass
    try:
        from redirecttracer.models import RedirectTrace
        counts["redirect"] = RedirectTrace.objects.count()
    except Exception:
        pass
    try:
        from emaildetector.models import EmailCheck
        counts["emailcheck"] = EmailCheck.objects.count()
    except Exception:
        pass
    try:
        if request.user.is_authenticated:
            from watchlist.models import WatchlistAlert
            counts["watchlist_alerts"] = WatchlistAlert.objects.filter(
                entry__user=request.user, acknowledged=False
            ).count()
    except Exception:
        pass
    return {"sidebar_counts": counts}
