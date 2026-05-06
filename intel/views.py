import re
from django.shortcuts import render, redirect
from django.contrib import messages
from django_ratelimit.decorators import ratelimit
from .forms import IntelForm
from .models import ThreatReport
from services import virustotal, abuseipdb
from services.api_key_resolver import get_api_keys
from services.urlhaus import check_urlhaus
from services.shodan_service import get_shodan_intel

IP_RE   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


def _detect_type(indicator: str) -> str:
    if IP_RE.match(indicator):   return "IP"
    if HASH_RE.match(indicator): return "HASH"
    if indicator.startswith("http://") or indicator.startswith("https://"): return "URL"
    return "DOMAIN"


def _compute_risk(vt_positives, abuse_score, urlhaus_found=False):
    vt    = vt_positives or 0
    score = abuse_score  or 0
    if vt >= 5 or score >= 75 or urlhaus_found: return "CRITICAL"
    if vt >= 2 or score >= 50: return "HIGH"
    if vt >= 1 or score >= 25: return "MEDIUM"
    return "LOW"


def _recent_reports(user):
    qs = ThreatReport.objects.order_by("-queried_at")
    if user.is_authenticated:
        return qs.filter(user=user)[:5]
    return qs.filter(user=None)[:5]


@ratelimit(key="user_or_ip", rate="30/h", method="POST", block=True)
def intel_form_view(request):
    prefill = request.GET.get("prefill", "")
    if request.method == "POST":
        form = IntelForm(request.POST)
    else:
        form = IntelForm(initial={"indicator": prefill} if prefill else None)

    if request.method == "POST" and form.is_valid():
        indicator = form.cleaned_data["indicator"].strip()
        itype     = _detect_type(indicator)
        api_keys  = get_api_keys(request.user)

        vt_data, abuse_data, urlhaus_data = {}, {}, {}
        vt_positives, vt_total = None, None
        abuse_score, abuse_reports, country, isp = None, None, None, None

        if itype == "IP":
            vt_data      = virustotal.scan_ip(indicator, api_keys)
            abuse_data   = abuseipdb.check_ip(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
            shodan_data  = get_shodan_intel(indicator)
            if "error" not in abuse_data:
                abuse_score   = abuse_data.get("abuseConfidenceScore")
                abuse_reports = abuse_data.get("totalReports")
                country       = abuse_data.get("countryCode")
                isp           = abuse_data.get("isp")
        elif itype == "DOMAIN":
            vt_data      = virustotal.scan_domain(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
            shodan_data  = None
        elif itype == "URL":
            vt_data      = virustotal.scan_url(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
            shodan_data  = None
        elif itype == "HASH":
            vt_data     = virustotal.scan_hash(indicator, api_keys)
            shodan_data = None

        if "error" in vt_data:
            messages.error(request, f"VirusTotal error: {vt_data['error']}")
            return render(request, "intel/intel_form.html", {
                "form": form, "recent_reports": _recent_reports(request.user), "prefill": prefill,
            })

        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats:
            vt_positives = stats.get("malicious", 0)
            vt_total     = sum(stats.values())

        if itype in ("DOMAIN", "URL") and not country:
            country = vt_data.get("data", {}).get("attributes", {}).get("country")

        urlhaus_found = urlhaus_data.get("found", False)
        risk_level    = _compute_risk(vt_positives, abuse_score, urlhaus_found)

        report = ThreatReport.objects.create(
            user=request.user if request.user.is_authenticated else None,
            indicator=indicator, indicator_type=itype,
            vt_positives=vt_positives, vt_total=vt_total,
            abuse_confidence_score=abuse_score, abuse_total_reports=abuse_reports,
            country_code=country, isp=isp,
            risk_level=risk_level, raw_vt=vt_data, raw_abuse=abuse_data or None,
            raw_urlhaus=urlhaus_data if urlhaus_found else None,
            raw_shodan=shodan_data,
        )
        messages.success(request, "Threat intelligence lookup completed.")
        return redirect("intel:result", pk=report.pk)

    return render(request, "intel/intel_form.html", {
        "form": form, "recent_reports": _recent_reports(request.user), "prefill": prefill,
    })


def intel_result_view(request, pk):
    try:
        report = ThreatReport.objects.get(pk=pk)
    except ThreatReport.DoesNotExist:
        messages.error(request, "Threat report not found.")
        return redirect("intel:form")

    # Only owner or admin can view
    if not request.user.is_staff:
        if report.user is None or report.user != request.user:
            messages.error(request, "You do not have permission to view this result.")
            return redirect("intel:form")

    # Only owner or admin can view
    if not request.user.is_staff:
        if report.user is None or report.user != request.user:
            messages.error(request, "You do not have permission to view this result.")
            return redirect("intel:form")

    engines = []
    results_map = report.raw_vt.get("data", {}).get("attributes", {}).get("last_analysis_results", {}) if report.raw_vt else {}
    for engine, data in results_map.items():
        if data.get("category") in ("malicious", "suspicious"):
            engines.append({"name": engine, "category": data.get("category"), "result": data.get("result", "")})

    vt_pct = round((report.vt_positives / report.vt_total) * 100) if report.vt_total and report.vt_positives else 0

    urlhaus = report.raw_urlhaus or {}
    shodan  = report.raw_shodan  or {}
    vt_cached      = (report.raw_vt or {}).get("_cached", False)
    urlhaus_cached = urlhaus.get("_cached", False)

    return render(request, "intel/intel_result.html", {
        "report":          report,
        "flagged_engines": engines[:10],
        "vt_pct":          vt_pct,
        "urlhaus":         urlhaus,
        "shodan":          shodan,
        "vt_cached":       vt_cached,
        "urlhaus_cached":  urlhaus_cached,
        "form":            IntelForm(),
    })
