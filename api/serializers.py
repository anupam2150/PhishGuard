from rest_framework import serializers
from scanner.models import ScanResult
from intel.models import ThreatReport
from correlation.models import CampaignScan, Campaign, URLRecord
from bulk_scanner.models import BulkScan, BulkScanResult


# ── Scanner ───────────────────────────────────────────────────────────────────

class ScanResultSerializer(serializers.ModelSerializer):
    ssl_risk_flags  = serializers.SerializerMethodField()
    ssl_available   = serializers.SerializerMethodField()
    phishtank_source = serializers.SerializerMethodField()

    class Meta:
        model  = ScanResult
        fields = [
            "id", "url", "domain", "scanned_at", "risk_level",
            "vt_positives", "vt_total",
            "gsb_flagged",
            "phishtank_flagged", "phishtank_source",
            "whois_registrar", "domain_age_days",
            "ssl_available", "ssl_risk_flags",
            "screenshot_path",
        ]
        read_only_fields = fields

    def get_ssl_risk_flags(self, obj):
        return (obj.raw_ssl or {}).get("ssl_risk_flags", [])

    def get_ssl_available(self, obj):
        return (obj.raw_ssl or {}).get("ssl_available", False)

    def get_phishtank_source(self, obj):
        return (obj.raw_phishtank or {}).get("source", "")


# ── Intel ─────────────────────────────────────────────────────────────────────

class IntelResultSerializer(serializers.ModelSerializer):
    urlhaus_found  = serializers.SerializerMethodField()
    urlhaus_status = serializers.SerializerMethodField()
    shodan_ports   = serializers.SerializerMethodField()
    shodan_vulns   = serializers.SerializerMethodField()

    class Meta:
        model  = ThreatReport
        fields = [
            "id", "indicator", "indicator_type", "queried_at", "risk_level",
            "vt_positives", "vt_total",
            "abuse_confidence_score", "abuse_total_reports",
            "country_code", "isp",
            "urlhaus_found", "urlhaus_status",
            "shodan_ports", "shodan_vulns",
        ]
        read_only_fields = fields

    def get_urlhaus_found(self, obj):
        return (obj.raw_urlhaus or {}).get("found", False)

    def get_urlhaus_status(self, obj):
        return (obj.raw_urlhaus or {}).get("status", "")

    def get_shodan_ports(self, obj):
        return (obj.raw_shodan or {}).get("open_ports", [])

    def get_shodan_vulns(self, obj):
        return (obj.raw_shodan or {}).get("vulns", [])


# ── Correlation ───────────────────────────────────────────────────────────────

class URLRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model  = URLRecord
        fields = [
            "id", "raw_url", "domain", "ip_address", "subnet",
            "hosting_provider", "keywords_found",
            "entropy_score", "suspicion_score", "suspicion_label",
        ]


class CampaignSerializer(serializers.ModelSerializer):
    urls = URLRecordSerializer(many=True, read_only=True)

    class Meta:
        model  = Campaign
        fields = [
            "campaign_index", "url_count",
            "confidence_score", "confidence_label",
            "shared_ip", "shared_provider",
            "reasons", "urls",
        ]


class CampaignScanSerializer(serializers.ModelSerializer):
    campaigns    = CampaignSerializer(many=True, read_only=True)
    progress_pct = serializers.SerializerMethodField()

    class Meta:
        model  = CampaignScan
        fields = [
            "id", "scan_label", "submitted_at", "status",
            "total_urls", "total_campaigns",
            "progress_pct", "campaigns",
        ]
        read_only_fields = fields

    def get_progress_pct(self, obj):
        # CampaignScan doesn't track per-URL progress like BulkScan,
        # so return 100 when COMPLETE, 0 otherwise.
        return 100 if obj.status == "COMPLETE" else 0


# ── Bulk Scanner ──────────────────────────────────────────────────────────────

class BulkScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model  = BulkScanResult
        fields = [
            "id", "url", "risk_level",
            "vt_positives", "gsb_flagged",
            "abuse_confidence", "error_message",
        ]


class BulkScanSerializer(serializers.ModelSerializer):
    results      = BulkScanResultSerializer(many=True, read_only=True)
    progress_pct = serializers.IntegerField(source="progress_pct", read_only=True)
    high_critical_count = serializers.IntegerField(source="high_critical_count", read_only=True)

    class Meta:
        model  = BulkScan
        fields = [
            "id", "uploaded_file_name", "submitted_at", "status",
            "total_urls", "completed", "failed",
            "progress_pct", "high_critical_count",
            "celery_task_id", "results",
        ]
        read_only_fields = fields
