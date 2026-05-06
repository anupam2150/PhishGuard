from django.urls import path
from . import views

app_name = "correlation"

urlpatterns = [
    path("", views.index, name="correlation_index"),
    path("process/<int:scan_id>/", views.process_scan, name="correlation_process"),
    path("results/<int:scan_id>/", views.results, name="correlation_results"),
    path("results/<int:scan_id>/campaign/<int:campaign_index>/", views.campaign_detail, name="correlation_detail"),
    path("history/", views.scan_history, name="correlation_history"),
]
