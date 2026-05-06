import csv
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django_ratelimit.decorators import ratelimit

from services.api_key_resolver import get_api_keys
from .forms import BulkScanForm
from .models import BulkScan, BulkScanResult
from .tasks import run_bulk_scan


def _user_scan_qs(request):
    u = request.user
    qs = BulkScan.objects.order_by("-submitted_at")
    return qs.filter(user=u) if u.is_authenticated else qs.filter(user=None)


@ratelimit(key="user_or_ip", rate="5/h", method="POST", block=True)
def upload_view(request):
    recent = _user_scan_qs(request)[:10]
    form   = BulkScanForm(request.POST or None, request.FILES or None)

    if request.method == "POST" and form.is_valid():
        urls     = form.cleaned_data["parsed_urls"]
        filename = request.FILES["file"].name

        # Create the BulkScan and pre-create all result rows (url only)
        scan = BulkScan.objects.create(
            user=request.user if request.user.is_authenticated else None,
            uploaded_file_name=filename,
            total_urls=len(urls),
            status="QUEUED",
        )
        BulkScanResult.objects.bulk_create([
            BulkScanResult(bulk_scan=scan, url=url) for url in urls
        ])

        # Resolve API keys now (in the web process) and pass as plain dict to task
        api_keys = get_api_keys(request.user)
        task     = run_bulk_scan.delay(scan.pk, api_keys)

        scan.celery_task_id = task.id
        scan.save(update_fields=["celery_task_id"])

        messages.success(request, f"Queued {len(urls)} URLs for scanning.")
        return redirect("bulk_scanner:results", pk=scan.pk)

    return render(request, "bulk_scanner/upload.html", {"form": form, "recent": recent})


def status_view(request, pk):
    """JSON polling endpoint — returns progress for the live progress bar."""
    scan = get_object_or_404(BulkScan, pk=pk)

    completed = scan.completed
    failed    = scan.failed
    total     = scan.total_urls

    # While the task is running, try to get finer-grained progress from Celery
    if scan.status == "PROCESSING" and scan.celery_task_id:
        try:
            from celery.result import AsyncResult
            result = AsyncResult(scan.celery_task_id)
            if result.state == "PROGRESS" and isinstance(result.info, dict):
                completed = result.info.get("completed", completed)
        except Exception:
            pass  # fall back to DB counters

    processed = completed + failed
    percent   = round((processed / total) * 100) if total else 0

    return JsonResponse({
        "status":    scan.status,
        "completed": completed,
        "failed":    failed,
        "total":     total,
        "percent":   percent,
    })


def results_view(request, pk):
    scan    = get_object_or_404(BulkScan, pk=pk)
    results = scan.results.order_by("-risk_level", "url")

    risk_filter = request.GET.get("risk", "")
    if risk_filter:
        results = results.filter(risk_level=risk_filter.upper())

    risk_counts = {
        "CRITICAL": scan.results.filter(risk_level="CRITICAL").count(),
        "HIGH":     scan.results.filter(risk_level="HIGH").count(),
        "MEDIUM":   scan.results.filter(risk_level="MEDIUM").count(),
        "LOW":      scan.results.filter(risk_level="LOW").count(),
        "ERROR":    scan.results.filter(risk_level="ERROR").count(),
    }

    return render(request, "bulk_scanner/results.html", {
        "scan":        scan,
        "results":     results,
        "risk_counts": risk_counts,
        "risk_filter": risk_filter.upper(),
    })


def download_csv_view(request, pk):
    scan = get_object_or_404(BulkScan, pk=pk)

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="bulk_scan_{scan.pk}.csv"'

    writer = csv.writer(response)
    writer.writerow(["URL", "Risk Level", "VT Positives", "GSB Flagged", "Abuse Confidence Score", "Error"])
    for r in scan.results.order_by("-risk_level", "url"):
        writer.writerow([
            r.url,
            r.risk_level,
            r.vt_positives if r.vt_positives is not None else "",
            r.gsb_flagged  if r.gsb_flagged  is not None else "",
            r.abuse_confidence if r.abuse_confidence is not None else "",
            r.error_message,
        ])

    return response
