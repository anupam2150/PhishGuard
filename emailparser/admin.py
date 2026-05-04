from django.contrib import admin
from .models import EmailScan

@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ("sender", "risk_level", "spf_result", "dkim_result", "dmarc_result", "submitted_at")
    list_filter = ("risk_level", "spf_result", "dkim_result", "dmarc_result")
    search_fields = ("sender",)
