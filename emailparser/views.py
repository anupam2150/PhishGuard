from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import EmailHeaderForm
from .models import EmailScan
from .utils import parse_headers


def _recent_scans(user):
    qs = EmailScan.objects.order_by("-submitted_at")
    if user.is_authenticated:
        return qs.filter(user=user)[:5]
    return qs.filter(user=None)[:5]


def email_form_view(request):
    prefill = request.GET.get("prefill", "")
    if request.method == "POST":
        form = EmailHeaderForm(request.POST)
    else:
        form = EmailHeaderForm(initial={"raw_headers": prefill} if prefill else None)

    if request.method == "POST" and form.is_valid():
        try:
            parsed = parse_headers(form.cleaned_data["raw_headers"])
        except Exception as e:
            messages.error(request, f"Failed to parse headers: {e}")
            return render(request, "emailparser/email_form.html", {
                "form": form, "recent_scans": _recent_scans(request.user), "prefill": prefill,
            })
        scan = EmailScan.objects.create(
            user=request.user if request.user.is_authenticated else None,
            **parsed
        )
        messages.success(request, "Email headers analyzed successfully.")
        return redirect("emailparser:result", pk=scan.pk)

    return render(request, "emailparser/email_form.html", {
        "form": form, "recent_scans": _recent_scans(request.user), "prefill": prefill,
    })


def email_result_view(request, pk):
    try:
        scan = EmailScan.objects.get(pk=pk)
    except EmailScan.DoesNotExist:
        messages.error(request, "Email scan result not found.")
        return redirect("emailparser:form")

    # Only owner or admin can view
    if not request.user.is_staff:
        if scan.user is None or scan.user != request.user:
            messages.error(request, "You do not have permission to view this result.")
            return redirect("emailparser:form")
    return render(request, "emailparser/email_result.html", {
        "scan": scan,
        "form": EmailHeaderForm(),
    })
