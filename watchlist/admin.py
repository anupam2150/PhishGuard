from django.contrib import admin
from .models import WatchlistAlert, WatchlistEntry


class WatchlistAlertInline(admin.TabularInline):
    model         = WatchlistAlert
    extra         = 0
    readonly_fields = ("previous_risk", "new_risk", "detected_at", "acknowledged")


@admin.register(WatchlistEntry)
class WatchlistEntryAdmin(admin.ModelAdmin):
    list_display  = ("indicator", "indicator_type", "user", "last_risk_level", "last_scanned_at", "alert_on_change")
    list_filter   = ("indicator_type", "alert_on_change")
    search_fields = ("indicator", "user__username")
    inlines       = [WatchlistAlertInline]


@admin.register(WatchlistAlert)
class WatchlistAlertAdmin(admin.ModelAdmin):
    list_display  = ("entry", "previous_risk", "new_risk", "detected_at", "acknowledged")
    list_filter   = ("acknowledged", "new_risk")
    actions       = ["mark_acknowledged"]

    @admin.action(description="Mark selected alerts as acknowledged")
    def mark_acknowledged(self, request, queryset):
        queryset.update(acknowledged=True)
