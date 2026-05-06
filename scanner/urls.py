from django.urls import path
from . import views

app_name = "scanner"

urlpatterns = [
    path("", views.scan_view, name="scan"),
    path("result/<int:pk>/", views.result_view, name="result"),
    path("result/<int:pk>/pdf/", views.download_pdf, name="download_pdf"),
]
