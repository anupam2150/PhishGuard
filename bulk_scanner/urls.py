from django.urls import path
from . import views

app_name = "bulk_scanner"

urlpatterns = [
    path("",                    views.upload_view,      name="upload"),
    path("<int:pk>/status/",    views.status_view,      name="status"),
    path("<int:pk>/results/",   views.results_view,     name="results"),
    path("<int:pk>/download/",  views.download_csv_view, name="download_csv"),
]
