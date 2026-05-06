"""
PhishTank integration.
Live API:   https://checkurl.phishtank.com/checkurl/
Offline DB: https://data.phishtank.com/data/online-valid.json.gz
            Downloaded once per day, cached in Django's cache framework.

Set PHISHTANK_KEY in .env for the live API.
If the key is missing or the live call fails, the offline method is used automatically.
"""

import gzip
import io
import json
import logging
import os

import requests
from django.core.cache import cache

logger = logging.getLogger(__name__)

_LIVE_URL      = "https://checkurl.phishtank.com/checkurl/"
_DB_URL        = "https://data.phishtank.com/data/online-valid.json.gz"
_TIMEOUT       = 10
_DB_CACHE_KEY  = "phishtank_db"
_DB_CACHE_TTL  = 86400          # 24 hours in seconds
_NOT_FOUND     = {"in_database": False}


# ── Live API ──────────────────────────────────────────────────────────────────

def check_phishtank(url: str) -> dict:
    """
    Query the PhishTank live API for a single URL.

    Returns:
      {
        "in_database":      bool,
        "verified":         bool,
        "valid":            bool,
        "phish_detail_url": str,
      }
    Falls back to check_phishtank_offline() if the key is missing or the
    request fails.
    """
    api_key = os.getenv("PHISHTANK_KEY", "").strip()

    if not api_key:
        logger.debug("PHISHTANK_KEY not set — using offline check")
        return check_phishtank_offline(url)

    try:
        resp = requests.post(
            _LIVE_URL,
            data={
                "url":     url,
                "format":  "json",
                "app_key": api_key,
            },
            headers={"User-Agent": "PhishGuard/1.0"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        logger.warning("PhishTank live API failed (%s) — falling back to offline", exc)
        return check_phishtank_offline(url)

    results = data.get("results", {})
    in_db   = results.get("in_database", False)

    return {
        "in_database":      bool(in_db),
        "verified":         bool(results.get("verified", False)),
        "valid":            bool(results.get("valid", False)),
        "phish_detail_url": results.get("phish_detail_page", ""),
        "source":           "live",
    }


# ── Offline cached DB ─────────────────────────────────────────────────────────

def _load_phishtank_db() -> set:
    """
    Return the set of known-phishing URLs from the cached PhishTank DB.
    Downloads and caches the gzipped JSON if the cache is cold or expired.
    Returns an empty set on any failure.
    """
    cached = cache.get(_DB_CACHE_KEY)
    if cached is not None:
        return cached

    logger.info("Downloading PhishTank offline DB from %s", _DB_URL)
    try:
        resp = requests.get(
            _DB_URL,
            headers={"User-Agent": "PhishGuard/1.0"},
            timeout=30,
            stream=True,
        )
        resp.raise_for_status()

        raw_gz   = resp.content
        raw_json = gzip.decompress(raw_gz)
        entries  = json.loads(raw_json)

        # Build a set of lowercase URLs for O(1) lookup
        url_set = {entry["url"].lower() for entry in entries if entry.get("url")}

        cache.set(_DB_CACHE_KEY, url_set, _DB_CACHE_TTL)
        logger.info("PhishTank offline DB cached: %d entries", len(url_set))
        return url_set

    except Exception as exc:
        logger.warning("Failed to load PhishTank offline DB: %s", exc)
        return set()


def check_phishtank_offline(url: str) -> dict:
    """
    Check a URL against the locally cached PhishTank database.
    Much faster than the live API — no per-request network call after the
    first daily download.

    Returns the same shape as check_phishtank() with source="offline".
    """
    url_set   = _load_phishtank_db()
    in_db     = url.lower() in url_set

    return {
        "in_database":      in_db,
        "verified":         in_db,   # all entries in online-valid.json are verified
        "valid":            in_db,
        "phish_detail_url": "",
        "source":           "offline",
    }
