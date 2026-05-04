from django.urls import path
from . import views

app_name = "emailparser"

urlpatterns = [
    path("", views.email_form_view, name="form"),
    path("result/<int:pk>/", views.email_result_view, name="result"),
]
