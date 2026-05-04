from django.urls import path
from . import views

app_name = "intel"

urlpatterns = [
    path("", views.intel_form_view, name="form"),
    path("result/<int:pk>/", views.intel_result_view, name="result"),
]
