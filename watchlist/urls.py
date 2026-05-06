from django.urls import path
from . import views

app_name = "watchlist"

urlpatterns = [
    path("",                          views.watchlist_list,    name="list"),
    path("<int:pk>/delete/",          views.watchlist_delete,  name="delete"),
    path("alerts/",                   views.alerts_list,       name="alerts"),
    path("alerts/<int:pk>/ack/",      views.acknowledge_alert, name="acknowledge"),
    path("alerts/ack-all/",           views.acknowledge_all,   name="acknowledge_all"),
]
