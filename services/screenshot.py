"""
Screenshot capture service.

Primary:  APIFlash (https://apiflash.com) — 500 free screenshots/month.
Fallback: html2image — fetches raw HTML via requests and renders it locally.

Controlled by SCREENSHOT_ENABLED in settings (default False).
"""

import logging
import os
import re
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

_TIMEOUT        = 15          # seconds for every outbound HTTP call
_SCREENSHOT_DIR = "screenshots"
_APIFLASH_BASE  = "https://api.apiflash.com/v1/urltoimage"


# ── URL sanitisation ──────────────────────────────────────────────────────────

def _sanitise_url(url: str) -> str | None:
    """
    Strip credentials from the URL and reject non-http(s) schemes.
    Returns the cleaned URL string, or None if the URL is unsafe/invalid.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    if parsed.scheme not in ("http", "https"):
        return None

    # Rebuild without username/password
    clean = urlunparse((
        parsed.scheme,
        parsed.hostname + (f":{parsed.port}" if parsed.port else ""),
        parsed.path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
    return clean


# ── Storage helpers ───────────────────────────────────────────────────────────

def _screenshot_path(scan_id: str) -> tuple[Path, str]:
    """
    Returns (absolute_path, relative_media_path) for a given scan_id.
    Creates the directory if it doesn't exist.
    """
    media_root = Path(settings.MEDIA_ROOT)
    directory  = media_root / _SCREENSHOT_DIR
    directory.mkdir(parents=True, exist_ok=True)

    filename      = re.sub(r"[^\w\-]", "_", str(scan_id)) + ".jpg"
    absolute_path = directory / filename
    relative_path = f"{_SCREENSHOT_DIR}/{filename}"
    return absolute_path, relative_path


# ── Primary: APIFlash ─────────────────────────────────────────────────────────

def _capture_apiflash(url: str, dest: Path) -> bool:
    """
    Download a screenshot from APIFlash and save to dest.
    Returns True on success.
    """
    access_key = os.getenv("APIFLASH_KEY", "")
    if not access_key:
        logger.debug("APIFLASH_KEY not set — skipping APIFlash capture")
        return False

    params = {
        "access_key": access_key,
        "url":        url,
        "width":      1280,
        "height":     800,
        "format":     "jpeg",
        "quality":    80,
        "fresh":      "true",       # always fetch live, not cached
        "no_ads":     "true",
        "no_cookie_banners": "true",
    }

    try:
        resp = requests.get(_APIFLASH_BASE, params=params, timeout=_TIMEOUT, stream=True)
        content_type = resp.headers.get("Content-Type", "")

        if resp.status_code != 200 or "image" not in content_type:
            # APIFlash returns JSON errors even on non-200
            logger.warning("APIFlash error %s: %s", resp.status_code, resp.text[:200])
            return False

        dest.write_bytes(resp.content)
        logger.info("APIFlash screenshot saved: %s", dest)
        return True

    except requests.exceptions.RequestException as exc:
        logger.warning("APIFlash request failed: %s", exc)
        return False


# ── Fallback: html2image ──────────────────────────────────────────────────────

def _capture_html2image(url: str, dest: Path) -> bool:
    """
    Fetch the page HTML via requests, then render it to an image using
    html2image.  Saves to dest.  Returns True on success.
    """
    try:
        from html2image import Html2Image
    except ImportError:
        logger.warning("html2image not installed — fallback unavailable")
        return False

    try:
        # Fetch raw HTML
        page = requests.get(url, timeout=_TIMEOUT, headers={"User-Agent": "PhishGuard/1.0"})
        html = page.text
    except requests.exceptions.RequestException as exc:
        logger.warning("html2image fetch failed for %s: %s", url, exc)
        return False

    try:
        hti = Html2Image(
            output_path=str(dest.parent),
            custom_flags=["--no-sandbox", "--disable-gpu", "--headless"],
        )
        hti.screenshot(
            html_str=html,
            save_as=dest.name,
            size=(1280, 800),
        )
        if dest.exists() and dest.stat().st_size > 0:
            logger.info("html2image screenshot saved: %s", dest)
            return True
        logger.warning("html2image produced an empty file for %s", url)
        return False

    except Exception as exc:
        logger.warning("html2image render failed for %s: %s", url, exc)
        return False


# ── Public API ────────────────────────────────────────────────────────────────

def capture_screenshot(url: str, scan_id: str) -> str | None:
    """
    Capture a screenshot of *url* and save it under MEDIA_ROOT/screenshots/.

    Returns the relative media path (e.g. "screenshots/42.jpg") on success,
    or None if screenshots are disabled, the URL is unsafe, or all methods fail.
    """
    if not getattr(settings, "SCREENSHOT_ENABLED", False):
        return None

    clean_url = _sanitise_url(url)
    if not clean_url:
        logger.warning("capture_screenshot: rejected unsafe URL %r", url)
        return None

    dest, relative = _screenshot_path(scan_id)

    # 1. Try APIFlash
    if _capture_apiflash(clean_url, dest):
        return relative

    # 2. Fallback to html2image
    if _capture_html2image(clean_url, dest):
        return relative

    logger.warning("capture_screenshot: all methods failed for %s", clean_url)
    return None
