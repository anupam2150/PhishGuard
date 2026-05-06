"""
PhishGuard REST API views.

All endpoints require JWT or Session authentication unless noted.
Rate limits: authenticated 100/day, anonymous 10/day (configured in settings).
"""

import re
from datetime import datetime, timezone as tz, timedelta

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

from scanner.models import ScanResult
from intel.models import ThreatReport
from correlation.models import CampaignScan, Campaign, URLRecord
from bulk_scanner.models import BulkScan

from .serializers import (
    ScanResultSerializer,
    IntelResultSerializer,
    CampaignScanSerializer,
    BulkScanSerializer,
)

_IP_RE   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")


# ── Shared helper ─────────────────────────────────────────────────────────────

def _user_filter(qs, request):
    u = request.user
    return qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)


# ── API root (browsable) ──────────────────────────────────────────────────────

class ApiRootView(APIView):
    """
    GET /api/
    PhishGuard REST API — endpoint directory.
    Authenticate with: POST /api/token/  →  Authorization: Bearer <access>
    """

    def get(self, request):
        base = request.build_absolute_uri("/api/")
        return Response({
            "info": "PhishGuard REST API v1",
            "authentication": {
                "obtain_token":  base + "token/",
                "refresh_token": base + "token/refresh/",
                "verify_token":  base + "token/verify/",
            },
            "endpoints": {
                "me":          base + "me/",
                "stats":       base + "stats/",
                "scan":        {"POST": base + "scan/",   "GET_list": base + "scans/",      "GET_detail": base + "scans/{id}/"},
                "intel":       {"POST": base + "intel/",  "GET_list": base + "intel/list/", "GET_detail": base + "intel/{id}/"},
                "correlate":   {"POST": base + "correlate/", "GET_list": base + "campaigns/", "GET_detail": base + "campaigns/{id}/"},
                "bulk":        {"GET_list": base + "bulk/", "GET_detail": base + "bulk/{id}/"},
            },
            "filters": {
                "scans":  "?risk=LOW|MEDIUM|HIGH|CRITICAL",
                "intel":  "?type=IP|DOMAIN|URL|HASH",
            },
        })


# ── POST /api/scan/  ──────────────────────────────────────────────────────────

class ScanSubmitView(APIView):
    """
    POST /api/scan/
    Body: {"url": "https://..."}
    Runs the full scanner pipeline: VirusTotal + GSB + PhishTank + SSL + WHOIS.
    Returns the created ScanResult.
    """
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        from urllib.parse import urlparse
        import whois
        from services import virustotal, safebrowsing
        from services.api_key_resolver import get_api_keys
        from services.phishtank import check_phishtank
        from services.ssl_analyzer import analyze_ssl

        url = (request.data.get("url") or "").strip()
        if not url:
            return Response({"error": "url is required"}, status=status.HTTP_400_BAD_REQUEST)
        if not (url.startswith("http://") or url.startswith("https://")):
            return Response({"error": "url must start with http:// or https://"}, status=status.HTTP_400_BAD_REQUEST)

        domain   = urlparse(url).netloc
        api_keys = get_api_keys(request.user)

        vt_data = virustotal.scan_url(url, api_keys)
        if "error" in vt_data:
            return Response({"error": vt_data["error"]}, status=status.HTTP_502_BAD_GATEWAY)

        stats        = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        vt_positives = stats.get("malicious", 0)
        vt_total     = sum(stats.values()) if stats else 0
        gsb_flagged  = safebrowsing.check_url(url, api_keys)
        pt_result    = check_phishtank(url)
        pt_flagged   = pt_result.get("in_database", False)
        ssl_data     = analyze_ssl(domain) if url.startswith("https://") else {"ssl_available": False}
        ssl_risky    = bool(ssl_data.get("ssl_risk_flags"))

        if vt_positives >= 5 or gsb_flagged or pt_flagged:
            risk = "CRITICAL"
        elif vt_positives >= 2 or ssl_risky:
            risk = "HIGH"
        elif vt_positives >= 1:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        try:
            w = whois.whois(domain)
            registrar = w.registrar or None
            creation  = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_days = None
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=tz.utc)
                age_days = (datetime.now(tz.utc) - creation).days
        except Exception:
            registrar, age_days = None, None

        result = ScanResult.objects.create(
            user=request.user if request.user.is_authenticated else None,
            url=url, domain=domain,
            vt_positives=vt_positives, vt_total=vt_total,
            gsb_flagged=gsb_flagged, risk_level=risk,
            whois_registrar=registrar, domain_age_days=age_days,
            raw_vt_response=vt_data, raw_gsb_response={"flagged": gsb_flagged},
            phishtank_flagged=pt_flagged, raw_phishtank=pt_result,
            raw_ssl=ssl_data,
        )
        return Response(ScanResultSerializer(result).data, status=status.HTTP_201_CREATED)


# ── GET /api/scans/  &  GET /api/scans/{id}/  ─────────────────────────────────

class ScanResultListView(generics.ListAPIView):
    """
    GET /api/scans/
    Paginated scan history for the current user.
    Filter: ?risk=HIGH
    """
    serializer_class = ScanResultSerializer

    def get_queryset(self):
        qs   = ScanResult.objects.order_by("-scanned_at")
        risk = self.request.query_params.get("risk")
        if risk:
            qs = qs.filter(risk_level=risk.upper())
        return _user_filter(qs, self.request)


class ScanResultDetailView(generics.RetrieveAPIView):
    """GET /api/scans/{id}/ — single scan result (user-scoped)."""
    serializer_class = ScanResultSerializer

    def get_queryset(self):
        return _user_filter(ScanResult.objects.all(), self.request)


# ── POST /api/intel/  ─────────────────────────────────────────────────────────

class IntelSubmitView(APIView):
    """
    POST /api/intel/
    Body: {"indicator": "1.2.3.4" | "evil.com" | "https://..." | "<hash>"}
    Runs VT + AbuseIPDB (for IPs) + URLhaus. Returns the created ThreatReport.
    """
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        from services import virustotal, abuseipdb
        from services.api_key_resolver import get_api_keys
        from services.urlhaus import check_urlhaus

        indicator = (request.data.get("indicator") or "").strip()
        if not indicator:
            return Response({"error": "indicator is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Detect type
        if _IP_RE.match(indicator):
            itype = "IP"
        elif _HASH_RE.match(indicator):
            itype = "HASH"
        elif indicator.startswith("http://") or indicator.startswith("https://"):
            itype = "URL"
        else:
            itype = "DOMAIN"

        api_keys     = get_api_keys(request.user)
        vt_data      = {}
        abuse_data   = {}
        urlhaus_data = {}
        vt_positives = vt_total = None
        abuse_score  = abuse_reports = country = isp = None

        if itype == "IP":
            vt_data      = virustotal.scan_ip(indicator, api_keys)
            abuse_data   = abuseipdb.check_ip(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
            if "error" not in abuse_data:
                abuse_score   = abuse_data.get("abuseConfidenceScore")
                abuse_reports = abuse_data.get("totalReports")
                country       = abuse_data.get("countryCode")
                isp           = abuse_data.get("isp")
        elif itype == "DOMAIN":
            vt_data      = virustotal.scan_domain(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
        elif itype == "URL":
            vt_data      = virustotal.scan_url(indicator, api_keys)
            urlhaus_data = check_urlhaus(indicator)
        elif itype == "HASH":
            vt_data = virustotal.scan_hash(indicator, api_keys)

        if "error" in vt_data:
            return Response({"error": vt_data["error"]}, status=status.HTTP_502_BAD_GATEWAY)

        stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats:
            vt_positives = stats.get("malicious", 0)
            vt_total     = sum(stats.values())

        if itype in ("DOMAIN", "URL") and not country:
            country = vt_data.get("data", {}).get("attributes", {}).get("country")

        urlhaus_found = urlhaus_data.get("found", False)
        vt  = vt_positives or 0
        scr = abuse_score  or 0
        if vt >= 5 or scr >= 75 or urlhaus_found:
            risk = "CRITICAL"
        elif vt >= 2 or scr >= 50:
            risk = "HIGH"
        elif vt >= 1 or scr >= 25:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        report = ThreatReport.objects.create(
            user=request.user if request.user.is_authenticated else None,
            indicator=indicator, indicator_type=itype,
            vt_positives=vt_positives, vt_total=vt_total,
            abuse_confidence_score=abuse_score, abuse_total_reports=abuse_reports,
            country_code=country, isp=isp,
            risk_level=risk, raw_vt=vt_data, raw_abuse=abuse_data or None,
            raw_urlhaus=urlhaus_data if urlhaus_found else None,
        )
        return Response(IntelResultSerializer(report).data, status=status.HTTP_201_CREATED)


# ── GET /api/intel/list/  &  GET /api/intel/{id}/  ───────────────────────────

class IntelResultListView(generics.ListAPIView):
    """
    GET /api/intel/list/
    Paginated threat intel history. Filter: ?type=IP
    """
    serializer_class = IntelResultSerializer

    def get_queryset(self):
        qs    = ThreatReport.objects.order_by("-queried_at")
        itype = self.request.query_params.get("type")
        if itype:
            qs = qs.filter(indicator_type=itype.upper())
        return _user_filter(qs, self.request)


class IntelResultDetailView(generics.RetrieveAPIView):
    """GET /api/intel/{id}/ — single threat report (user-scoped)."""
    serializer_class = IntelResultSerializer

    def get_queryset(self):
        return _user_filter(ThreatReport.objects.all(), self.request)


# ── POST /api/correlate/  ─────────────────────────────────────────────────────

class CorrelateSubmitView(APIView):
    """
    POST /api/correlate/
    Body: {"urls": ["https://...", ...], "label": "optional label"}
    Runs the full correlation pipeline synchronously.
    Returns the CampaignScan with all detected campaigns.
    Min 2 URLs, max 100.
    """
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        from correlation.services.url_parser import URLFeatureExtractor
        from correlation.services.ip_resolver import resolve_ip, get_subnet
        from correlation.services.hosting import get_hosting_provider
        from correlation.services.correlator import CampaignCorrelator
        from correlation.services.confidence import ConfidenceScorer

        urls  = request.data.get("urls") or []
        label = (request.data.get("label") or "").strip()

        if not isinstance(urls, list) or len(urls) < 2:
            return Response({"error": "urls must be a list of at least 2 URLs"}, status=status.HTTP_400_BAD_REQUEST)
        if len(urls) > 100:
            return Response({"error": "Maximum 100 URLs per request"}, status=status.HTTP_400_BAD_REQUEST)

        # Validate each URL
        valid_urls = [u for u in urls if isinstance(u, str) and (u.startswith("http://") or u.startswith("https://"))]
        if len(valid_urls) < 2:
            return Response({"error": "At least 2 valid http/https URLs required"}, status=status.HTTP_400_BAD_REQUEST)

        scan = CampaignScan.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_label=label,
            total_urls=len(valid_urls),
            status="PROCESSING",
        )

        try:
            scorer    = ConfidenceScorer()
            url_dicts = []

            for raw_url in valid_urls:
                features   = URLFeatureExtractor(raw_url).extract()
                ip         = resolve_ip(features["domain"])
                subnet     = get_subnet(ip)
                provider   = get_hosting_provider(ip)
                individual = scorer.score_individual({**features})
                url_dicts.append({
                    "raw_url":               raw_url,
                    "domain":                features["domain"],
                    "ip_address":            ip,
                    "subnet":                subnet,
                    "hosting_provider":      provider,
                    "keywords_found":        features["keywords_found"],
                    "structural_fingerprint": features["structural_fingerprint"],
                    "entropy_score":         features["entropy_score"],
                    "suspicion_score":       individual["score"],
                    "suspicion_label":       individual["label"],
                    "tld":                   features.get("tld", ""),
                    "hyphen_count":          features.get("hyphen_count", 0),
                    "is_ip_url":             features.get("is_ip_url", False),
                    "path_depth":            features.get("path_depth", 0),
                })

            records    = URLRecord.objects.bulk_create([
                URLRecord(
                    scan=scan, raw_url=d["raw_url"], domain=d["domain"],
                    ip_address=d["ip_address"], subnet=d["subnet"],
                    hosting_provider=d["hosting_provider"],
                    keywords_found=d["keywords_found"],
                    structural_fingerprint=d["structural_fingerprint"],
                    entropy_score=d["entropy_score"],
                    suspicion_score=d["suspicion_score"],
                    suspicion_label=d["suspicion_label"],
                ) for d in url_dicts
            ])
            record_map = {r.raw_url: r for r in records}
            clusters   = CampaignCorrelator(url_dicts).correlate()

            for idx, cluster in enumerate(clusters):
                c_score = scorer.score(cluster)
                c_label = scorer.score_label(c_score)
                reasons = CampaignCorrelator.explain_cluster(cluster)
                ips     = [u["ip_address"] for u in cluster if u.get("ip_address") and u["ip_address"] != "UNRESOLVED"]
                provs   = [u["hosting_provider"] for u in cluster if u.get("hosting_provider") and u["hosting_provider"] != "UNKNOWN"]
                campaign = Campaign.objects.create(
                    scan=scan, campaign_index=idx + 1,
                    url_count=len(cluster),
                    confidence_score=c_score, confidence_label=c_label,
                    shared_ip=ips[0] if len(set(ips)) == 1 and ips else None,
                    shared_provider=provs[0] if len(set(provs)) == 1 and provs else None,
                    reasons=reasons,
                )
                campaign.urls.set([record_map[u["raw_url"]] for u in cluster if u["raw_url"] in record_map])

            scan.total_campaigns = len(clusters)
            scan.status = "COMPLETE"
            scan.save()

        except Exception as exc:
            scan.status = "FAILED"
            scan.save()
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        scan_obj = CampaignScan.objects.prefetch_related("campaigns__urls").get(pk=scan.pk)
        return Response(CampaignScanSerializer(scan_obj).data, status=status.HTTP_201_CREATED)


# ── GET /api/campaigns/  &  GET /api/campaigns/{id}/  ────────────────────────

class CampaignScanListView(generics.ListAPIView):
    """GET /api/campaigns/ — paginated campaign scan history."""
    serializer_class = CampaignScanSerializer

    def get_queryset(self):
        return _user_filter(
            CampaignScan.objects.prefetch_related("campaigns__urls").order_by("-submitted_at"),
            self.request,
        )


class CampaignScanDetailView(generics.RetrieveAPIView):
    """GET /api/campaigns/{id}/ — single campaign scan with all campaigns and URLs."""
    serializer_class = CampaignScanSerializer

    def get_queryset(self):
        return _user_filter(
            CampaignScan.objects.prefetch_related("campaigns__urls"),
            self.request,
        )


# ── GET /api/bulk/  &  GET /api/bulk/{id}/  ───────────────────────────────────

class BulkScanListView(generics.ListAPIView):
    """GET /api/bulk/ — paginated bulk scan history."""
    serializer_class = BulkScanSerializer

    def get_queryset(self):
        return _user_filter(BulkScan.objects.order_by("-submitted_at"), self.request)


class BulkScanDetailView(generics.RetrieveAPIView):
    """GET /api/bulk/{id}/ — single bulk scan with all URL results."""
    serializer_class = BulkScanSerializer

    def get_queryset(self):
        return _user_filter(BulkScan.objects.prefetch_related("results"), self.request)


# ── GET /api/stats/  ──────────────────────────────────────────────────────────

class StatsView(APIView):
    """
    GET /api/stats/
    Returns the current user's aggregate scan statistics.
    """

    def get(self, request):
        u      = request.user
        cutoff = timezone.now() - timedelta(days=30)

        def _uf(qs):
            return qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)

        total_scans = (
            _uf(ScanResult.objects).count()
            + _uf(ThreatReport.objects).count()
        )
        high_critical_count = (
            _uf(ScanResult.objects.filter(risk_level__in=["HIGH", "CRITICAL"])).count()
            + _uf(ThreatReport.objects.filter(risk_level__in=["HIGH", "CRITICAL"])).count()
        )
        campaigns_detected = Campaign.objects.filter(
            scan__in=_uf(CampaignScan.objects)
        ).count()

        # Risk breakdown for URL scans
        risk_breakdown = {
            row["risk_level"]: row["count"]
            for row in _uf(ScanResult.objects)
            .values("risk_level")
            .annotate(count=Count("id"))
        }

        # Last 30 days activity
        recent_scans = _uf(ScanResult.objects.filter(scanned_at__gte=cutoff)).count()

        return Response({
            "total_scans":          total_scans,
            "high_critical_count":  high_critical_count,
            "campaigns_detected":   campaigns_detected,
            "risk_breakdown":       risk_breakdown,
            "scans_last_30_days":   recent_scans,
        })


# ── GET /api/me/  ─────────────────────────────────────────────────────────────

class MeView(APIView):
    """GET /api/me/ — current user info and API key status."""

    def get(self, request):
        u       = request.user
        profile = getattr(u, "profile", None)
        return Response({
            "id":                u.pk,
            "username":          u.username,
            "email":             u.email,
            "personal_api_key":  profile.personal_api_key if profile else None,
            "has_vt_key":        bool(profile and profile.vt_api_key),
            "has_abuseipdb_key": bool(profile and profile.abuseipdb_key),
            "has_gsb_key":       bool(profile and profile.gsb_api_key),
        })
