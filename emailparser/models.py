from django.db import models


class EmailScan(models.Model):
    RISK_CHOICES = [("LOW", "LOW"), ("MEDIUM", "MEDIUM"), ("HIGH", "HIGH")]
    AUTH_CHOICES = [("pass", "pass"), ("fail", "fail"), ("neutral", "neutral"), ("none", "none")]

    submitted_at = models.DateTimeField(auto_now_add=True)
    sender = models.CharField(max_length=512)
    reply_to = models.CharField(max_length=512, null=True, blank=True)
    return_path = models.CharField(max_length=512, null=True, blank=True)
    spf_result = models.CharField(max_length=10, choices=AUTH_CHOICES, default="none")
    dkim_result = models.CharField(max_length=10, choices=AUTH_CHOICES, default="none")
    dmarc_result = models.CharField(max_length=10, choices=AUTH_CHOICES, default="none")
    x_mailer = models.CharField(max_length=255, null=True, blank=True)
    hop_count = models.IntegerField(default=0)
    suspicious_flags = models.JSONField(default=list)
    risk_level = models.CharField(max_length=10, choices=RISK_CHOICES, default="LOW")

    def __str__(self):
        return f"{self.sender} — {self.risk_level} ({self.submitted_at:%Y-%m-%d})"
