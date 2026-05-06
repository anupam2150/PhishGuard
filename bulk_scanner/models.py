from django.conf import settings
from django.db import models


class BulkScan(models.Model):
    STATUS_CHOICES = [
        ("QUEUED",      "QUEUED"),
        ("PROCESSING",  "PROCESSING"),
        ("COMPLETE",    "COMPLETE"),
        ("FAILED",      "FAILED"),
    ]
    RISK_CHOICES = [
        ("LOW",      "LOW"),
        ("MEDIUM",   "MEDIUM"),
        ("HIGH",     "HIGH"),
        ("CRITICAL", "CRITICAL"),
        ("ERROR",    "ERROR"),
    ]

    user               = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    uploaded_file_name = models.CharField(max_length=255)
    total_urls         = models.IntegerField(default=0)
    completed          = models.IntegerField(default=0)
    failed             = models.IntegerField(default=0)
    status             = models.CharField(max_length=20, choices=STATUS_CHOICES, default="QUEUED")
    submitted_at       = models.DateTimeField(auto_now_add=True)
    celery_task_id     = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"BulkScan #{self.pk} — {self.uploaded_file_name} ({self.status})"

    @property
    def progress_pct(self):
        if not self.total_urls:
            return 0
        return round(((self.completed + self.failed) / self.total_urls) * 100)

    @property
    def high_critical_count(self):
        return self.results.filter(risk_level__in=["HIGH", "CRITICAL"]).count()


class BulkScanResult(models.Model):
    RISK_CHOICES = [
        ("LOW",      "LOW"),
        ("MEDIUM",   "MEDIUM"),
        ("HIGH",     "HIGH"),
        ("CRITICAL", "CRITICAL"),
        ("ERROR",    "ERROR"),
    ]

    bulk_scan         = models.ForeignKey(BulkScan, on_delete=models.CASCADE, related_name="results")
    url               = models.URLField(max_length=500)
    risk_level        = models.CharField(max_length=10, choices=RISK_CHOICES, default="LOW")
    vt_positives      = models.IntegerField(null=True, blank=True)
    gsb_flagged       = models.BooleanField(null=True, blank=True)
    abuse_confidence  = models.IntegerField(null=True, blank=True)
    error_message     = models.TextField(blank=True)

    def __str__(self):
        return f"{self.url} — {self.risk_level}"
