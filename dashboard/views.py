from django.utils import timezone
from django.db.models import Count, Q
from django.shortcuts import render
from django.core.paginator import Paginator
from datetime import timedelta
from collections import defaultdict
import json
import re as _re
import socket
import requests as _requests
from django.core.cache import cache as _cache

from scanner.models import ScanResult
from emailparser.models import EmailScan
from intel.models import ThreatReport

_IP_RE      = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_GEO_TTL    = 86400
_IPINFO_URL = "https://ipinfo.io/{ip}/json"


def _geo(ip: str):
    key    = f"ipinfo_{ip}"
    cached = _cache.get(key)
    if cached is not None:
        return cached or None
    try:
        resp = _requests.get(_IPINFO_URL.format(ip=ip), timeout=5)
        resp.raise_for_status()
        data = resp.json()
        loc  = data.get("loc", "")
        if not loc or "," not in loc:
            _cache.set(key, False, _GEO_TTL)
            return None
        lat, lon = map(float, loc.split(","))
        if not lat or not lon:
            _cache.set(key, False, _GEO_TTL)
            return None
        result = {
            "lat":     lat,
            "lon":     lon,
            "country": data.get("country", ""),
            "city":    data.get("city", ""),
        }
        _cache.set(key, result, _GEO_TTL)
        return result
    except Exception:
        _cache.set(key, False, _GEO_TTL)
        return None


def overview(request):
    today = timezone.now().date()
    u = request.user

    def _uf(qs):
        return qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)

    total_scans = (
        _uf(ScanResult.objects).count()
        + _uf(EmailScan.objects).count()
        + _uf(ThreatReport.objects).count()
    )

    high_critical_today = (
        _uf(ScanResult.objects.filter(scanned_at__date=today, risk_level__in=["HIGH", "CRITICAL"])).count()
        + _uf(EmailScan.objects.filter(submitted_at__date=today, risk_level__in=["HIGH", "CRITICAL"])).count()
        + _uf(ThreatReport.objects.filter(queried_at__date=today, risk_level__in=["HIGH", "CRITICAL"])).count()
    )
    high_critical_all = (
        _uf(ScanResult.objects.filter(risk_level__in=["HIGH", "CRITICAL"])).count()
        + _uf(EmailScan.objects.filter(risk_level__in=["HIGH", "CRITICAL"])).count()
        + _uf(ThreatReport.objects.filter(risk_level__in=["HIGH", "CRITICAL"])).count()
    )

    recent_scans  = _uf(ScanResult.objects).order_by("-scanned_at")[:10]
    recent_emails = _uf(EmailScan.objects).order_by("-submitted_at")[:10]
    recent_intel  = _uf(ThreatReport.objects).order_by("-queried_at")[:10]

    risk_order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_counts = {r: 0 for r in risk_order}
    for qs in [
        _uf(ScanResult.objects).values("risk_level").annotate(c=Count("id")),
        _uf(EmailScan.objects).values("risk_level").annotate(c=Count("id")),
        _uf(ThreatReport.objects).values("risk_level").annotate(c=Count("id")),
    ]:
        for row in qs:
            risk_counts[row["risk_level"]] = risk_counts.get(row["risk_level"], 0) + row["c"]

    total_campaign_scans = 0
    high_confidence_campaigns = 0
    recent_campaign_scans = []
    try:
        from correlation.models import CampaignScan, Campaign
        base_cs = CampaignScan.objects.filter(user=u) if u.is_authenticated else CampaignScan.objects.filter(user=None)
        total_campaign_scans = base_cs.count()
        high_confidence_campaigns = Campaign.objects.filter(scan__in=base_cs, confidence_score__gte=0.75).count()
        recent_campaign_scans = base_cs.filter(status="COMPLETE").order_by("-submitted_at")[:3]
    except Exception:
        pass

    cutoff_14 = timezone.now() - timedelta(days=14)
    trend_qs  = (
        _uf(ScanResult.objects.filter(scanned_at__gte=cutoff_14))
        .extra(select={"day": "date(scanned_at)"})
        .values("day", "risk_level")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    trend_map = defaultdict(lambda: {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0})
    for row in trend_qs:
        day = str(row["day"])
        trend_map[day][row["risk_level"]] = row["count"]

    today_dt = timezone.now().date()
    all_days = [(today_dt - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    trend_labels   = all_days
    trend_critical = [trend_map[d]["CRITICAL"] for d in all_days]
    trend_high     = [trend_map[d]["HIGH"]     for d in all_days]
    trend_medium   = [trend_map[d]["MEDIUM"]   for d in all_days]
    trend_low      = [trend_map[d]["LOW"]      for d in all_days]

    cutoff_30 = timezone.now() - timedelta(days=30)
    top_domains_qs = (
        _uf(ScanResult.objects.filter(
            scanned_at__gte=cutoff_30,
            risk_level__in=["HIGH", "CRITICAL"],
        ))
        .values("domain")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    top_domain_labels = [r["domain"] for r in top_domains_qs]
    top_domain_counts = [r["count"]  for r in top_domains_qs]

    return render(request, "dashboard/overview.html", {
        "total_scans":              total_scans,
        "high_critical_today":      high_critical_today,
        "high_critical_all":        high_critical_all,
        "recent_scans":             recent_scans,
        "recent_emails":            recent_emails,
        "recent_intel":             recent_intel,
        "risk_labels":              list(risk_counts.keys()),
        "risk_data":                list(risk_counts.values()),
        "total_campaign_scans":     total_campaign_scans,
        "high_confidence_campaigns": high_confidence_campaigns,
        "recent_campaign_scans":    recent_campaign_scans,
        "trend_labels":             trend_labels,
        "trend_critical":           trend_critical,
        "trend_high":               trend_high,
        "trend_medium":             trend_medium,
        "trend_low":                trend_low,
        "top_domain_labels":        top_domain_labels,
        "top_domain_counts":        top_domain_counts,
    })


def global_search(request):
    query = request.GET.get("q", "").strip()
    u = request.user
    url_results = email_results = intel_results = []
    total = 0

    if query and len(query) >= 2:
        base_scan  = ScanResult.objects.filter(user=u)   if u.is_authenticated else ScanResult.objects.filter(user=None)
        base_email = EmailScan.objects.filter(user=u)    if u.is_authenticated else EmailScan.objects.filter(user=None)
        base_intel = ThreatReport.objects.filter(user=u) if u.is_authenticated else ThreatReport.objects.filter(user=None)

        url_results = base_scan.filter(
            Q(url__icontains=query) | Q(domain__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-scanned_at")[:20]
        email_results = base_email.filter(
            Q(sender__icontains=query) | Q(spf_result__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-submitted_at")[:20]
        intel_results = base_intel.filter(
            Q(indicator__icontains=query) | Q(indicator_type__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-queried_at")[:20]
        total = len(url_results) + len(email_results) + len(intel_results)

    return render(request, "dashboard/search_results.html", {
        "query":         query,
        "url_results":   url_results,
        "email_results": email_results,
        "intel_results": intel_results,
        "total":         total,
    })


def high_critical_today_view(request):
    today = timezone.now().date()
    u = request.user
    qs = ScanResult.objects.filter(risk_level__in=["HIGH", "CRITICAL"], scanned_at__date=today)
    qs = qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)
    qs = qs.order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title":        "High / Critical Scans — Today",
        "filter_label": "Today",
        "count":        qs.count(),
        "page_obj":     page,
    })


def high_critical_alltime_view(request):
    u = request.user
    qs = ScanResult.objects.filter(risk_level__in=["HIGH", "CRITICAL"])
    qs = qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)
    qs = qs.order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title":        "High / Critical Scans — All Time",
        "filter_label": "All Time",
        "count":        qs.count(),
        "page_obj":     page,
    })


def all_scans_view(request):
    u = request.user
    qs = ScanResult.objects.all()
    qs = qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)
    qs = qs.order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title":        "All URL Scans",
        "filter_label": "All",
        "count":        qs.count(),
        "page_obj":     page,
    })


def threat_map(request):
    u        = request.user
    cutoff   = timezone.now() - timedelta(days=30)
    seen_ips = {}
    RISK_RANK = {"CRITICAL": 2, "HIGH": 1}

    # Source 1: ThreatReport IP lookups
    intel_qs = ThreatReport.objects.filter(
        queried_at__gte=cutoff,
        indicator_type="IP",
        risk_level__in=["HIGH", "CRITICAL"],
    )
    if u.is_authenticated:
        intel_qs = intel_qs.filter(user=u)

    for report in intel_qs.only("indicator", "risk_level", "queried_at"):
        ip = report.indicator.strip()
        if not _IP_RE.match(ip):
            continue
        rank = RISK_RANK.get(report.risk_level, 0)
        if ip not in seen_ips or rank > RISK_RANK.get(seen_ips[ip]["risk_level"], 0):
            seen_ips[ip] = {
                "ip":         ip,
                "risk_level": report.risk_level,
                "indicator":  ip,
                "scan_date":  report.queried_at.strftime("%Y-%m-%d"),
            }

    # Source 2: HIGH/CRITICAL URL scans — resolve domain to IP
    scan_qs = ScanResult.objects.filter(
        scanned_at__gte=cutoff,
        risk_level__in=["HIGH", "CRITICAL"],
    )
    if u.is_authenticated:
        scan_qs = scan_qs.filter(user=u)

    for scan in scan_qs.only("domain", "risk_level", "scanned_at"):
        domain = scan.domain
        if not domain:
            continue
        cache_key = f"ipinfo_domain_{domain}"
        cached_ip = _cache.get(cache_key)
        if cached_ip is None:
            try:
                old = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3)
                try:
                    ip = socket.gethostbyname(domain)
                finally:
                    socket.setdefaulttimeout(old)
            except Exception:
                ip = None
            _cache.set(cache_key, ip or "", 3600)
        else:
            ip = cached_ip or None

        if not ip or not _IP_RE.match(ip):
            continue

        rank = RISK_RANK.get(scan.risk_level, 0)
        if ip not in seen_ips or rank > RISK_RANK.get(seen_ips[ip]["risk_level"], 0):
            seen_ips[ip] = {
                "ip":         ip,
                "risk_level": scan.risk_level,
                "indicator":  domain,
                "scan_date":  scan.scanned_at.strftime("%Y-%m-%d"),
            }

    points = []
    for ip, meta in seen_ips.items():
        geo = _geo(ip)
        if not geo or not geo["lat"] or not geo["lon"]:
            continue
        points.append({
            "ip":         ip,
            "lat":        float(geo["lat"]),
            "lon":        float(geo["lon"]),
            "country":    geo["country"],
            "city":       geo["city"],
            "risk_level": meta["risk_level"],
            "indicator":  meta["indicator"],
            "scan_date":  meta["scan_date"],
        })

    countries = len({p["country"] for p in points if p["country"]})

    return render(request, "dashboard/threat_map.html", {
        "threat_data_json": json.dumps(points),
        "threat_count":     len(points),
        "country_count":    countries,
    })
