"""
watchlist/scheduler.py

Periodic re-scan job for all WatchlistEntry objects that are due (never scanned
or last scanned > 6 hours ago).  Registered in WatchlistConfig.ready() via
APScheduler's BackgroundScheduler so it runs inside the Django web process —
no separate worker needed on Render free tier.
"""

import logging
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

logger = logging.getLogger(__name__)

_RESCAN_INTERVAL_HOURS = 6


def _compute_risk(vt_positives: int, gsb_flagged: bool = False, abuse_score: int = 0) -> str:
    if vt_positives >= 5 or gsb_flagged or abuse_score >= 75:
        return "CRITICAL"
    if vt_positives >= 2 or abuse_score >= 50:
        return "HIGH"
    if vt_positives >= 1 or abuse_score >= 25:
        return "MEDIUM"
    return "LOW"


def _scan_entry(entry) -> str | None:
    """
    Run the appropriate service call for the entry's indicator type.
    Returns the computed risk level string, or None on hard failure.
    """
    from services import virustotal, abuseipdb
    from services.api_key_resolver import get_api_keys

    api_keys = get_api_keys(entry.user)

    try:
        if entry.indicator_type == "IP":
            vt_data    = virustotal.scan_ip(entry.indicator, api_keys)
            abuse_data = abuseipdb.check_ip(entry.indicator, api_keys)
            if "error" in vt_data:
                logger.warning("VT error for %s: %s", entry.indicator, vt_data["error"])
                return None
            stats        = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_positives = stats.get("malicious", 0)
            abuse_score  = abuse_data.get("abuseConfidenceScore", 0) if "error" not in abuse_data else 0
            return _compute_risk(vt_positives, abuse_score=abuse_score)

        elif entry.indicator_type == "DOMAIN":
            vt_data = virustotal.scan_domain(entry.indicator, api_keys)
            if "error" in vt_data:
                logger.warning("VT error for %s: %s", entry.indicator, vt_data["error"])
                return None
            stats        = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_positives = stats.get("malicious", 0)
            return _compute_risk(vt_positives)

        elif entry.indicator_type == "URL":
            from services import safebrowsing
            vt_data     = virustotal.scan_url(entry.indicator, api_keys)
            gsb_flagged = safebrowsing.check_url(entry.indicator, api_keys)
            if "error" in vt_data:
                logger.warning("VT error for %s: %s", entry.indicator, vt_data["error"])
                return None
            stats        = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            vt_positives = stats.get("malicious", 0)
            return _compute_risk(vt_positives, gsb_flagged=gsb_flagged)

    except Exception as exc:
        logger.exception("Unexpected error scanning %s: %s", entry.indicator, exc)
        return None


def _send_alert_email(entry, previous_risk: str, new_risk: str) -> None:
    """Send a plain-text alert email to the entry owner."""
    email = entry.user.email
    if not email:
        return

    subject = f"\u26a0 PhishGuard Alert: Risk change detected for {entry.indicator}"
    body = render_to_string("watchlist/alert_email.txt", {
        "entry":         entry,
        "previous_risk": previous_risk,
        "new_risk":      new_risk,
        "site_url":      getattr(settings, "SITE_URL", "https://phishguard-tool.onrender.com"),
        "now":           timezone.now(),
    })

    try:
        send_mail(
            subject=subject,
            message=body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True,
        )
        logger.info("Alert email sent to %s for %s", email, entry.indicator)
    except Exception as exc:
        logger.warning("Failed to send alert email to %s: %s", email, exc)


def rescan_watchlist() -> None:
    """
    Main scheduled job.  Loads all due WatchlistEntry rows, re-scans each one,
    creates WatchlistAlert records on risk changes, and sends alert emails.
    """
    # Import models here (inside the function) to avoid AppRegistryNotReady
    # errors when the scheduler starts before Django's app registry is fully loaded.
    from watchlist.models import WatchlistAlert, WatchlistEntry

    cutoff = timezone.now() - timedelta(hours=_RESCAN_INTERVAL_HOURS)
    due_entries = WatchlistEntry.objects.filter(
        last_scanned_at__isnull=True
    ) | WatchlistEntry.objects.filter(
        last_scanned_at__lt=cutoff
    )
    due_entries = due_entries.select_related("user", "user__profile")

    total = due_entries.count()
    if total == 0:
        logger.debug("rescan_watchlist: no entries due for rescan")
        return

    logger.info("rescan_watchlist: scanning %d due entries", total)

    for entry in due_entries:
        new_risk = _scan_entry(entry)
        if new_risk is None:
            continue  # scan failed — don't update timestamps, retry next cycle

        previous_risk = entry.last_risk_level or ""
        now           = timezone.now()

        # Detect risk change
        if previous_risk and new_risk != previous_risk and entry.alert_on_change:
            WatchlistAlert.objects.create(
                entry=entry,
                previous_risk=previous_risk,
                new_risk=new_risk,
            )
            logger.info(
                "Alert created for %s: %s → %s",
                entry.indicator, previous_risk, new_risk,
            )
            _send_alert_email(entry, previous_risk, new_risk)

        # Always update scan metadata
        entry.last_risk_level = new_risk
        entry.last_scanned_at = now
        entry.save(update_fields=["last_risk_level", "last_scanned_at"])

    logger.info("rescan_watchlist: completed %d entries", total)
