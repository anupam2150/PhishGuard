from django.utils import timezone
from django.db.models import Count, Q
from django.shortcuts import render
from django.core.paginator import Paginator
from scanner.models import ScanResult
from emailparser.models import EmailScan
from intel.models import ThreatReport
from services.news import get_cyber_news


def overview(request):
    today = timezone.now().date()

    total_scans = ScanResult.objects.count() + EmailScan.objects.count() + ThreatReport.objects.count()

    high_critical_today = (
        ScanResult.objects.filter(scanned_at__date=today, risk_level__in=["HIGH", "CRITICAL"]).count()
        + EmailScan.objects.filter(submitted_at__date=today, risk_level__in=["HIGH", "CRITICAL"]).count()
        + ThreatReport.objects.filter(queried_at__date=today, risk_level__in=["HIGH", "CRITICAL"]).count()
    )
    high_critical_all = (
        ScanResult.objects.filter(risk_level__in=["HIGH", "CRITICAL"]).count()
        + EmailScan.objects.filter(risk_level__in=["HIGH", "CRITICAL"]).count()
        + ThreatReport.objects.filter(risk_level__in=["HIGH", "CRITICAL"]).count()
    )

    recent_scans  = ScanResult.objects.order_by("-scanned_at")[:10]
    recent_emails = EmailScan.objects.order_by("-submitted_at")[:10]
    recent_intel  = ThreatReport.objects.order_by("-queried_at")[:10]

    risk_order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_counts = {r: 0 for r in risk_order}
    for qs in [
        ScanResult.objects.values("risk_level").annotate(c=Count("id")),
        EmailScan.objects.values("risk_level").annotate(c=Count("id")),
        ThreatReport.objects.values("risk_level").annotate(c=Count("id")),
    ]:
        for row in qs:
            risk_counts[row["risk_level"]] = risk_counts.get(row["risk_level"], 0) + row["c"]

    return render(request, "dashboard/overview.html", {
        "total_scans": total_scans,
        "high_critical_today": high_critical_today,
        "high_critical_all": high_critical_all,
        "recent_scans": recent_scans,
        "recent_emails": recent_emails,
        "recent_intel": recent_intel,
        "risk_labels": list(risk_counts.keys()),
        "risk_data": list(risk_counts.values()),
    })


def global_search(request):
    query = request.GET.get("q", "").strip()
    url_results = email_results = intel_results = []
    total = 0

    if query and len(query) >= 2:
        url_results   = ScanResult.objects.filter(
            Q(url__icontains=query) | Q(domain__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-scanned_at")[:20]

        email_results = EmailScan.objects.filter(
            Q(sender__icontains=query) | Q(spf_result__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-submitted_at")[:20]

        intel_results = ThreatReport.objects.filter(
            Q(indicator__icontains=query) | Q(indicator_type__icontains=query) | Q(risk_level__icontains=query)
        ).order_by("-queried_at")[:20]

        total = len(url_results) + len(email_results) + len(intel_results)

    return render(request, "dashboard/search_results.html", {
        "query": query,
        "url_results": url_results,
        "email_results": email_results,
        "intel_results": intel_results,
        "total": total,
    })


def high_critical_today_view(request):
    today = timezone.now().date()
    qs = ScanResult.objects.filter(
        risk_level__in=["HIGH", "CRITICAL"], scanned_at__date=today
    ).order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title": "High / Critical Scans — Today",
        "filter_label": "Today",
        "count": qs.count(),
        "page_obj": page,
    })


def high_critical_alltime_view(request):
    qs = ScanResult.objects.filter(
        risk_level__in=["HIGH", "CRITICAL"]
    ).order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title": "High / Critical Scans — All Time",
        "filter_label": "All Time",
        "count": qs.count(),
        "page_obj": page,
    })


def all_scans_view(request):
    qs = ScanResult.objects.all().order_by("-scanned_at")
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "dashboard/filtered_list.html", {
        "title": "All URL Scans",
        "filter_label": "All",
        "count": qs.count(),
        "page_obj": page,
    })
