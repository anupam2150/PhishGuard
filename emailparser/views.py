from django.shortcuts import render, redirect
from django.contrib import messages
from .forms import EmailHeaderForm
from .models import EmailScan
from .utils import parse_headers


def _recent_scans():
    return EmailScan.objects.order_by("-submitted_at")[:5]


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
                "form": form, "recent_scans": _recent_scans(), "prefill": prefill,
            })
        scan = EmailScan.objects.create(**parsed)
        messages.success(request, "Email headers analyzed successfully.")
        return redirect("emailparser:result", pk=scan.pk)

    return render(request, "emailparser/email_form.html", {
        "form": form, "recent_scans": _recent_scans(), "prefill": prefill,
    })


def email_result_view(request, pk):
    try:
        scan = EmailScan.objects.get(pk=pk)
    except EmailScan.DoesNotExist:
        messages.error(request, "Email scan result not found.")
        return redirect("emailparser:form")
    return render(request, "emailparser/email_result.html", {
        "scan": scan,
        "form": EmailHeaderForm(),
    })
