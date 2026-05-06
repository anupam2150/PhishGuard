def sidebar_counts(request):
    counts = {"scanner": 0, "email": 0, "intel": 0, "watchlist_alerts": 0}
    u = request.user

    def _uf(qs):
        return qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)

    try:
        from scanner.models import ScanResult
        counts["scanner"] = _uf(ScanResult.objects).count()
    except Exception:
        pass
    try:
        from emailparser.models import EmailScan
        counts["email"] = _uf(EmailScan.objects).count()
    except Exception:
        pass
    try:
        from intel.models import ThreatReport
        counts["intel"] = _uf(ThreatReport.objects).count()
    except Exception:
        pass
    try:
        if u.is_authenticated:
            from watchlist.models import WatchlistAlert
            counts["watchlist_alerts"] = WatchlistAlert.objects.filter(
                entry__user=u, acknowledged=False
            ).count()
    except Exception:
        pass
    return {"sidebar_counts": counts}
