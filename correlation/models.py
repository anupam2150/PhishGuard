from django.db import models


class CampaignScan(models.Model):
    STATUS_CHOICES = [
        ("PENDING", "PENDING"),
        ("PROCESSING", "PROCESSING"),
        ("COMPLETE", "COMPLETE"),
        ("FAILED", "FAILED"),
    ]
    scan_label = models.CharField(max_length=100, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    total_urls = models.IntegerField(default=0)
    total_campaigns = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="PENDING")

    def __str__(self):
        return f"{self.scan_label or 'Scan'} #{self.pk} — {self.status}"


class URLRecord(models.Model):
    scan = models.ForeignKey(CampaignScan, on_delete=models.CASCADE, related_name="url_records")
    raw_url = models.URLField(max_length=500)
    domain = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    subnet = models.CharField(max_length=20, blank=True, null=True)
    hosting_provider = models.CharField(max_length=100, blank=True, null=True)
    keywords_found = models.JSONField(default=list)
    structural_fingerprint = models.JSONField(default=list)
    entropy_score = models.FloatField(null=True, blank=True)
    suspicion_score = models.FloatField(null=True, blank=True)
    suspicion_label = models.CharField(max_length=20, blank=True, null=True)

    def __str__(self):
        return self.domain


class Campaign(models.Model):
    scan = models.ForeignKey(CampaignScan, on_delete=models.CASCADE, related_name="campaigns")
    campaign_index = models.IntegerField()
    url_count = models.IntegerField()
    confidence_score = models.FloatField()
    confidence_label = models.CharField(max_length=20)
    shared_ip = models.CharField(max_length=45, blank=True, null=True)
    shared_provider = models.CharField(max_length=100, blank=True, null=True)
    reasons = models.JSONField(default=list)
    urls = models.ManyToManyField(URLRecord, blank=True)

    def __str__(self):
        return f"Campaign #{self.campaign_index} — {self.confidence_label}"
