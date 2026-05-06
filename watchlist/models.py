from django.conf import settings
from django.db import models


class WatchlistEntry(models.Model):
    TYPE_CHOICES = [("DOMAIN", "DOMAIN"), ("IP", "IP"), ("URL", "URL")]

    user             = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="watchlist_entries")
    indicator        = models.CharField(max_length=500)
    indicator_type   = models.CharField(max_length=10, choices=TYPE_CHOICES)
    last_risk_level  = models.CharField(max_length=20, blank=True)
    last_scanned_at  = models.DateTimeField(null=True, blank=True)
    alert_on_change  = models.BooleanField(default=True)
    created_at       = models.DateTimeField(auto_now_add=True)
    notes            = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        unique_together = [("user", "indicator")]

    def __str__(self):
        return f"{self.indicator_type}:{self.indicator}"

    @property
    def unacknowledged_alerts(self):
        return self.alerts.filter(acknowledged=False).count()


class WatchlistAlert(models.Model):
    entry         = models.ForeignKey(WatchlistEntry, on_delete=models.CASCADE, related_name="alerts")
    previous_risk = models.CharField(max_length=20)
    new_risk      = models.CharField(max_length=20)
    detected_at   = models.DateTimeField(auto_now_add=True)
    acknowledged  = models.BooleanField(default=False)

    class Meta:
        ordering = ["-detected_at"]

    def __str__(self):
        return f"{self.entry.indicator}: {self.previous_risk} → {self.new_risk}"
