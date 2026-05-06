"""
PDF report generation service using WeasyPrint.
Renders a Django template to HTML then converts to PDF bytes.
"""

import logging
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)


def generate_scan_pdf(scan_result_id: int) -> bytes:
    """
    Load a ScanResult by ID, render the report HTML template,
    and return the PDF as raw bytes.
    Raises ScanResult.DoesNotExist if the ID is invalid.
    """
    from scanner.models import ScanResult
    import weasyprint

    result = ScanResult.objects.get(pk=scan_result_id)

    # Build flagged engines list from raw VT response
    engines = []
    results_map = (
        (result.raw_vt_response or {})
        .get("data", {})
        .get("attributes", {})
        .get("last_analysis_results", {})
    )
    for engine, data in results_map.items():
        if data.get("category") in ("malicious", "suspicious"):
            engines.append({
                "name":     engine,
                "category": data.get("category", ""),
                "result":   data.get("result", ""),
            })

    vt_pct = round((result.vt_positives / result.vt_total) * 100) if result.vt_total else 0
    ssl    = result.raw_ssl or {}

    html_string = render_to_string("reports/scan_report.html", {
        "result":          result,
        "flagged_engines": engines[:20],
        "vt_pct":          vt_pct,
        "ssl":             ssl,
        "phishtank":       result.raw_phishtank or {},
        "generated_at":    timezone.now(),
    })

    try:
        pdf_bytes = weasyprint.HTML(string=html_string).write_pdf()
        return pdf_bytes
    except Exception as exc:
        logger.error("WeasyPrint failed for scan %s: %s", scan_result_id, exc)
        raise
