from urllib.parse import urlparse
from datetime import datetime, timezone
import whois
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit
from .forms import ScanForm
from .models import ScanResult
from services import virustotal, safebrowsing
from services.api_key_resolver import get_api_keys
from services.screenshot import capture_screenshot
from services.phishtank import check_phishtank
from services.ssl_analyzer import analyze_ssl
from services.pdf_reporter import generate_scan_pdf


def _compute_risk(vt_positives, gsb_flagged, domain_age_days, phishtank_flagged=False, ssl_risky=False):
    if vt_positives >= 5 or gsb_flagged or phishtank_flagged:
        return "CRITICAL"
    if vt_positives >= 2 or ssl_risky:
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


def _recent_scans(user):
    qs = ScanResult.objects.order_by("-scanned_at")
    if user.is_authenticated:
        return qs.filter(user=user)[:5]
    return qs.filter(user=None)[:5]


@ratelimit(key="user_or_ip", rate="20/h", method="POST", block=True)
def scan_view(request):
    prefill = request.GET.get("prefill", "")
    if request.method == "POST":
        form = ScanForm(request.POST)
    else:
        form = ScanForm(initial={"url": prefill} if prefill else None)

    if request.method == "POST" and form.is_valid():
        url = form.cleaned_data["url"]
        domain = urlparse(url).netloc
        api_keys = get_api_keys(request.user)

        vt_data = virustotal.scan_url(url, api_keys)
        if "error" in vt_data:
            messages.error(request, f"VirusTotal error: {vt_data['error']}")
            return render(request, "scanner/scan_form.html", {
                "form": form, "recent_scans": _recent_scans(request.user), "prefill": prefill,
            })

        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_positives = stats.get("malicious", 0)
        vt_total = sum(stats.values()) if stats else 0
        vt_cached = vt_data.get("_cached", False)

        gsb_flagged = safebrowsing.check_url(url, api_keys)
        pt_result   = check_phishtank(url)
        pt_flagged  = pt_result.get("in_database", False)
        ssl_data    = analyze_ssl(domain) if url.startswith("https://") else {"ssl_available": False, "error": "HTTP only"}
        registrar, age_days = _whois_info(domain)

        # Factor SSL risk flags into overall risk
        ssl_flags   = ssl_data.get("ssl_risk_flags", [])
        ssl_risky   = bool(ssl_flags)
        risk_level  = _compute_risk(vt_positives, gsb_flagged, age_days, pt_flagged, ssl_risky)

        result = ScanResult.objects.create(
            user=request.user if request.user.is_authenticated else None,
            url=url, domain=domain,
            vt_positives=vt_positives, vt_total=vt_total,
            gsb_flagged=gsb_flagged, risk_level=risk_level,
            whois_registrar=registrar, domain_age_days=age_days,
            raw_vt_response=vt_data, raw_gsb_response={"flagged": gsb_flagged},
            phishtank_flagged=pt_flagged,
            raw_phishtank=pt_result,
            raw_ssl=ssl_data,
        )

        if getattr(settings, "SCREENSHOT_ENABLED", False) and risk_level in ("HIGH", "CRITICAL"):
            try:
                path = capture_screenshot(url, str(result.pk))
                if path:
                    result.screenshot_path = path
                    result.save(update_fields=["screenshot_path"])
            except Exception:
                pass  # screenshot failure must never break the scan result

        if vt_cached:
            messages.info(request, "⚡ Results served from cache — no new API quota used.")
        messages.success(request, "Scan completed successfully.")
        return redirect("scanner:result", pk=result.pk)

    return render(request, "scanner/scan_form.html", {
        "form": form, "recent_scans": _recent_scans(request.user), "prefill": prefill,
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

    vt_pct    = round((result.vt_positives / result.vt_total) * 100) if result.vt_total else 0
    vt_cached = result.raw_vt_response.get("_cached", False)

    return render(request, "scanner/scan_result.html", {
        "result":             result,
        "flagged_engines":    engines[:10],
        "vt_pct":             vt_pct,
        "vt_cached":          vt_cached,
        "scan_form":          ScanForm(),
        "screenshot_enabled": getattr(settings, "SCREENSHOT_ENABLED", False),
        "MEDIA_URL":          settings.MEDIA_URL,
        "phishtank":          result.raw_phishtank or {},
        "ssl":                result.raw_ssl or {},
    })


def download_pdf(request, pk):
    try:
        pdf_bytes = generate_scan_pdf(pk)
    except Exception as exc:
        messages.error(request, f"PDF generation failed: {exc}")
        return redirect("scanner:result", pk=pk)

    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="phishguard_scan_{pk}.pdf"'
    return response
