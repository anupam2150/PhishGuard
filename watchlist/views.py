from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .forms import WatchlistEntryForm
from .models import WatchlistAlert, WatchlistEntry


@login_required
def watchlist_list(request):
    entries = WatchlistEntry.objects.filter(user=request.user).prefetch_related("alerts")
    form    = WatchlistEntryForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        entry = form.save(commit=False)
        entry.user = request.user
        try:
            entry.save()
            messages.success(request, f"Added {entry.indicator} to your watchlist.")
        except Exception:
            messages.error(request, f"{entry.indicator} is already in your watchlist.")
        return redirect("watchlist:list")

    unacked_count = WatchlistAlert.objects.filter(
        entry__user=request.user, acknowledged=False
    ).count()

    return render(request, "watchlist/list.html", {
        "entries":       entries,
        "form":          form,
        "unacked_count": unacked_count,
    })


@login_required
def watchlist_delete(request, pk):
    entry = get_object_or_404(WatchlistEntry, pk=pk, user=request.user)
    if request.method == "POST":
        indicator = entry.indicator
        entry.delete()
        messages.success(request, f"Removed {indicator} from your watchlist.")
    return redirect("watchlist:list")


@login_required
def alerts_list(request):
    alerts = WatchlistAlert.objects.filter(
        entry__user=request.user
    ).select_related("entry").order_by("-detected_at")

    unacked_count = alerts.filter(acknowledged=False).count()

    return render(request, "watchlist/alerts.html", {
        "alerts":        alerts,
        "unacked_count": unacked_count,
    })


@login_required
def acknowledge_alert(request, pk):
    alert = get_object_or_404(WatchlistAlert, pk=pk, entry__user=request.user)
    if request.method == "POST":
        alert.acknowledged = True
        alert.save(update_fields=["acknowledged"])
    return redirect("watchlist:alerts")


@login_required
def acknowledge_all(request):
    if request.method == "POST":
        WatchlistAlert.objects.filter(
            entry__user=request.user, acknowledged=False
        ).update(acknowledged=True)
        messages.success(request, "All alerts acknowledged.")
    return redirect("watchlist:alerts")
