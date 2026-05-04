from django.contrib import admin
from .models import ThreatReport

@admin.register(ThreatReport)
class ThreatReportAdmin(admin.ModelAdmin):
    list_display = ("indicator", "indicator_type", "risk_level", "vt_positives", "abuse_confidence_score", "queried_at")
    list_filter = ("risk_level", "indicator_type")
    search_fields = ("indicator",)
