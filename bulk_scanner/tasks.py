import time
from celery import shared_task
from django.db import transaction
from django.db.models import F

# VT free tier: 4 requests/min — 1.5 s gap keeps us safely under the limit
_VT_RATE_DELAY = 1.5


@shared_task(bind=True)
def run_bulk_scan(self, bulk_scan_id: int, api_keys: dict):
    from .models import BulkScan, BulkScanResult
    from services import virustotal, safebrowsing

    try:
        scan = BulkScan.objects.get(pk=bulk_scan_id)
    except BulkScan.DoesNotExist:
        return

    scan.status = "PROCESSING"
    scan.celery_task_id = self.request.id or ""
    scan.save(update_fields=["status", "celery_task_id"])

    urls  = list(scan.results.values_list("url", flat=True))
    total = len(urls)

    try:
        for idx, url in enumerate(urls):
            result_obj = scan.results.get(url=url)

            # Report progress to Celery backend before each URL
            self.update_state(
                state="PROGRESS",
                meta={"completed": idx, "total": total, "current_url": url},
            )

            try:
                vt_data = virustotal.scan_url(url, api_keys)

                if "error" in vt_data:
                    result_obj.risk_level    = "ERROR"
                    result_obj.error_message = vt_data["error"]
                    result_obj.save(update_fields=["risk_level", "error_message"])
                    with transaction.atomic():
                        BulkScan.objects.filter(pk=bulk_scan_id).update(failed=F("failed") + 1)
                else:
                    stats        = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    vt_positives = stats.get("malicious", 0)
                    gsb_flagged  = safebrowsing.check_url(url, api_keys)

                    result_obj.vt_positives = vt_positives
                    result_obj.gsb_flagged  = gsb_flagged
                    result_obj.risk_level   = _compute_risk(vt_positives, gsb_flagged)
                    result_obj.save(update_fields=["vt_positives", "gsb_flagged", "risk_level"])
                    with transaction.atomic():
                        BulkScan.objects.filter(pk=bulk_scan_id).update(completed=F("completed") + 1)

            except Exception as exc:
                result_obj.risk_level    = "ERROR"
                result_obj.error_message = str(exc)
                result_obj.save(update_fields=["risk_level", "error_message"])
                with transaction.atomic():
                    BulkScan.objects.filter(pk=bulk_scan_id).update(failed=F("failed") + 1)

            # Respect VT free-tier rate limit between every URL
            if idx < total - 1:
                time.sleep(_VT_RATE_DELAY)

        # Final progress state before marking complete
        self.update_state(
            state="PROGRESS",
            meta={"completed": total, "total": total, "current_url": ""},
        )
        BulkScan.objects.filter(pk=bulk_scan_id).update(status="COMPLETE")

    except Exception as exc:
        # Unhandled exception in the outer loop — mark the whole scan failed
        BulkScan.objects.filter(pk=bulk_scan_id).update(status="FAILED")
        raise  # re-raise so Celery marks the task as FAILURE too


def _compute_risk(vt_positives: int, gsb_flagged: bool) -> str:
    if vt_positives >= 10:
        return "CRITICAL"
    if vt_positives >= 3 or gsb_flagged:
        return "HIGH"
    if vt_positives >= 1:
        return "MEDIUM"
    return "LOW"
