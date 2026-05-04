from django.contrib import admin
from django.urls import path, include
from dashboard.news_views import news_feed

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("dashboard.urls")),
    path("scanner/", include("scanner.urls")),
    path("email/", include("emailparser.urls")),
    path("intel/", include("intel.urls")),
    path("news-feed/", news_feed, name="news_feed"),
]
