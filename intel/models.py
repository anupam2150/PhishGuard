from django.conf import settings
from django.db import models


class ThreatReport(models.Model):
    RISK_CHOICES = [("LOW", "LOW"), ("MEDIUM", "MEDIUM"), ("HIGH", "HIGH"), ("CRITICAL", "CRITICAL")]
    TYPE_CHOICES = [("IP", "IP"), ("DOMAIN", "DOMAIN"), ("URL", "URL"), ("HASH", "HASH")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    indicator = models.CharField(max_length=2048)
    indicator_type = models.CharField(max_length=10, choices=TYPE_CHOICES)
    queried_at = models.DateTimeField(auto_now_add=True)
    vt_positives = models.IntegerField(null=True, blank=True)
    vt_total = models.IntegerField(null=True, blank=True)
    abuse_confidence_score = models.IntegerField(null=True, blank=True)
    abuse_total_reports = models.IntegerField(null=True, blank=True)
    country_code = models.CharField(max_length=10, null=True, blank=True)
    isp = models.CharField(max_length=255, null=True, blank=True)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default="LOW")
    raw_vt     = models.JSONField(null=True, blank=True)
    raw_abuse   = models.JSONField(null=True, blank=True)
    raw_urlhaus = models.JSONField(null=True, blank=True)
    raw_shodan  = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.indicator} ({self.indicator_type}) — {self.risk_level}"
