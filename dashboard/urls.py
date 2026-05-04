from django.urls import path
from . import views

app_name = "dashboard"

urlpatterns = [
    path("", views.overview, name="overview"),
    path("search/", views.global_search, name="global_search"),
    path("scans/today/", views.high_critical_today_view, name="high_critical_today"),
    path("scans/alltime/", views.high_critical_alltime_view, name="high_critical_alltime"),
    path("scans/all/", views.all_scans_view, name="all_scans"),
]
