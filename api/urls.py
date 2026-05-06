from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from . import views

urlpatterns = [
    # ── API root (browsable directory) ───────────────────────────────────────
    path("", views.ApiRootView.as_view(), name="api_root"),

    # ── JWT auth ──────────────────────────────────────────────────────────────
    path("token/",         TokenObtainPairView.as_view(), name="api_token_obtain"),
    path("token/refresh/", TokenRefreshView.as_view(),    name="api_token_refresh"),
    path("token/verify/",  TokenVerifyView.as_view(),     name="api_token_verify"),

    # ── Current user & stats ──────────────────────────────────────────────────
    path("me/",    views.MeView.as_view(),    name="api_me"),
    path("stats/", views.StatsView.as_view(), name="api_stats"),

    # ── URL Scanner ───────────────────────────────────────────────────────────
    # NOTE: literal paths must come before <int:pk> to avoid routing conflicts
    path("scan/",           views.ScanSubmitView.as_view(),     name="api_scan_submit"),
    path("scans/",          views.ScanResultListView.as_view(), name="api_scan_list"),
    path("scans/<int:pk>/", views.ScanResultDetailView.as_view(), name="api_scan_detail"),

    # ── Threat Intel ──────────────────────────────────────────────────────────
    path("intel/",           views.IntelSubmitView.as_view(),     name="api_intel_submit"),
    path("intel/list/",      views.IntelResultListView.as_view(), name="api_intel_list"),
    path("intel/<int:pk>/",  views.IntelResultDetailView.as_view(), name="api_intel_detail"),

    # ── Campaign Correlator ───────────────────────────────────────────────────
    path("correlate/",          views.CorrelateSubmitView.as_view(),  name="api_correlate_submit"),
    path("campaigns/",          views.CampaignScanListView.as_view(), name="api_campaign_list"),
    path("campaigns/<int:pk>/", views.CampaignScanDetailView.as_view(), name="api_campaign_detail"),

    # ── Bulk Scanner ──────────────────────────────────────────────────────────
    path("bulk/",          views.BulkScanListView.as_view(),   name="api_bulk_list"),
    path("bulk/<int:pk>/", views.BulkScanDetailView.as_view(), name="api_bulk_detail"),
]
