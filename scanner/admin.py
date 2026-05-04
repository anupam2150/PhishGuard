from django.contrib import admin
from .models import ScanResult

@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    list_display = ("domain", "risk_level", "vt_positives", "gsb_flagged", "scanned_at")
    list_filter = ("risk_level", "gsb_flagged")
    search_fields = ("domain", "url")
