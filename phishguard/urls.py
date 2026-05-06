from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from dashboard.news_views import news_feed

handler404 = "phishguard.views.custom_404"
handler500 = "phishguard.views.custom_500"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("dashboard.urls")),
    path("scanner/", include("scanner.urls")),
    path("email/", include("emailparser.urls")),
    path("intel/", include("intel.urls")),
    path("correlation/", include("correlation.urls")),
    path("accounts/", include("accounts.urls")),
    path("bulk/",       include("bulk_scanner.urls")),
    path("watchlist/",  include("watchlist.urls")),
    path("api/",        include("api.urls")),
    path("news-feed/",  news_feed, name="news_feed"),
]

# Serve uploaded media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
