from django.conf import settings
from django.db import models


class ScanResult(models.Model):
    RISK_CHOICES = [("LOW", "LOW"), ("MEDIUM", "MEDIUM"), ("HIGH", "HIGH"), ("CRITICAL", "CRITICAL")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    url = models.URLField(max_length=2048)
    scanned_at = models.DateTimeField(auto_now_add=True)
    domain = models.CharField(max_length=255)
    vt_positives = models.IntegerField(default=0)
    vt_total = models.IntegerField(default=0)
    gsb_flagged = models.BooleanField(default=False)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default="LOW")
    whois_registrar = models.CharField(max_length=255, null=True, blank=True)
    domain_age_days = models.IntegerField(null=True, blank=True)
    raw_vt_response  = models.JSONField(default=dict)
    raw_gsb_response  = models.JSONField(default=dict)
    phishtank_flagged = models.BooleanField(null=True, blank=True)
    raw_phishtank     = models.JSONField(null=True, blank=True)
    raw_ssl           = models.JSONField(null=True, blank=True)
    screenshot_path   = models.CharField(max_length=255, blank=True, default="")

    def __str__(self):
        return f"{self.domain} — {self.risk_level} ({self.scanned_at:%Y-%m-%d})"
