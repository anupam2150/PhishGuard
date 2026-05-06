from django.contrib import admin
from .models import BulkScan, BulkScanResult


class BulkScanResultInline(admin.TabularInline):
    model  = BulkScanResult
    extra  = 0
    fields = ("url", "risk_level", "vt_positives", "gsb_flagged", "error_message")
    readonly_fields = fields


@admin.register(BulkScan)
class BulkScanAdmin(admin.ModelAdmin):
    list_display   = ("pk", "uploaded_file_name", "user", "status", "total_urls", "completed", "failed", "submitted_at")
    list_filter    = ("status",)
    readonly_fields = ("celery_task_id", "submitted_at")
    inlines        = [BulkScanResultInline]
