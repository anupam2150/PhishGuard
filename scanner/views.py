from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import ScanForm
from .models import ScanResult
from services import virustotal, safebrowsing


def _compute_risk(vt_positives, gsb_flagged, domain_age_days):
    if vt_positives >= 5 or gsb_flagged:
        return "CRITICAL"
    if vt_positives >= 2:
        return "HIGH"
    if vt_positives == 1 or (domain_age_days is not None and domain_age_days < 30):
        return "MEDIUM"
    return "LOW"


def _whois_info(domain):
    try:
        w = whois.whois(domain)
        registrar = w.registrar or None
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = None
        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
        return registrar, age_days
    except Exception:
        return None, None


def _recent_scans():
    return ScanResult.objects.order_by("-scanned_at")[:5]


def scan_view(request):
    prefill = request.GET.get("prefill", "")
    if request.method == "POST":
        form = ScanForm(request.POST)
    else:
        form = ScanForm(initial={"url": prefill} if prefill else None)

    if request.method == "POST" and form.is_valid():
        url = form.cleaned_data["url"]
        domain = urlparse(url).netloc

        vt_data = virustotal.scan_url(url)
        if "error" in vt_data:
            messages.error(request, f"VirusTotal error: {vt_data['error']}")
            return render(request, "scanner/scan_form.html", {
                "form": form, "recent_scans": _recent_scans(), "prefill": prefill,
            })

        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_positives = stats.get("malicious", 0)
        vt_total = sum(stats.values()) if stats else 0

        gsb_flagged = safebrowsing.check_url(url)
        registrar, age_days = _whois_info(domain)
        risk_level = _compute_risk(vt_positives, gsb_flagged, age_days)

        result = ScanResult.objects.create(
            url=url, domain=domain,
            vt_positives=vt_positives, vt_total=vt_total,
            gsb_flagged=gsb_flagged, risk_level=risk_level,
            whois_registrar=registrar, domain_age_days=age_days,
            raw_vt_response=vt_data, raw_gsb_response={"flagged": gsb_flagged},
        )
        messages.success(request, "Scan completed successfully.")
        return redirect("scanner:result", pk=result.pk)

    return render(request, "scanner/scan_form.html", {
        "form": form, "recent_scans": _recent_scans(), "prefill": prefill,
    })


def result_view(request, pk):
    try:
        result = ScanResult.objects.get(pk=pk)
    except ScanResult.DoesNotExist:
        messages.error(request, "Scan result not found.")
        return redirect("scanner:scan")

    engines = []
    results_map = (
        result.raw_vt_response.get("data", {})
        .get("attributes", {})
        .get("last_analysis_results", {})
    )
    for engine, data in results_map.items():
        category = data.get("category", "undetected")
        if category in ("malicious", "suspicious"):
            engines.append({"name": engine, "category": category, "result": data.get("result", "")})

    vt_pct = round((result.vt_positives / result.vt_total) * 100) if result.vt_total else 0

    return render(request, "scanner/scan_result.html", {
        "result": result,
        "flagged_engines": engines[:10],
        "vt_pct": vt_pct,
        "scan_form": ScanForm(),
    })
