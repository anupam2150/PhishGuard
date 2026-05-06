"""
Shodan host intelligence service.
Requires SHODAN_API_KEY in .env (free account gives limited queries).
Results are cached in Django's cache framework for 24 hours per IP.
"""

import logging
import os

from django.core.cache import cache

logger = logging.getLogger(__name__)

_CACHE_TTL = 86400   # 24 hours


def get_shodan_intel(ip: str) -> dict | None:
    """
    Fetch Shodan host data for an IP address.

    Returns a normalised dict:
      {
        "org":         str,
        "isp":         str,
        "country":     str,
        "city":        str,
        "open_ports":  list[int],
        "banners":     list[str],   # first 3 service banners
        "vulns":       list[str],   # CVE IDs
        "last_update": str,
        "hostnames":   list[str],
      }
    Returns None if:
      - SHODAN_API_KEY is not set
      - The IP is not in Shodan's database
      - Any API / network error occurs
    """
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    if not api_key:
        logger.debug("SHODAN_API_KEY not set — skipping Shodan lookup")
        return None

    cache_key = f"shodan_{ip}"
    cached    = cache.get(cache_key)
    if cached is not None:
        return cached  # may be the sentinel {} meaning "not found"

    try:
        import shodan
        api  = shodan.Shodan(api_key)
        host = api.host(ip)
    except Exception as exc:
        # shodan.APIError is raised for "No information available" (404-equivalent)
        logger.debug("Shodan lookup failed for %s: %s", ip, exc)
        cache.set(cache_key, None, _CACHE_TTL)
        return None

    result = _parse_host(host)
    cache.set(cache_key, result, _CACHE_TTL)
    return result


def _parse_host(host: dict) -> dict:
    data = host.get("data", [])

    # Open ports — deduplicated and sorted
    open_ports = sorted({item.get("port") for item in data if item.get("port")})

    # First 3 non-empty service banners
    banners = []
    for item in data:
        banner = (item.get("data") or "").strip()
        if banner:
            # Truncate very long banners to keep the dict lean
            banners.append(banner[:300])
        if len(banners) >= 3:
            break

    # CVE IDs from the top-level "vulns" dict (key = CVE ID)
    vulns = sorted(host.get("vulns", {}).keys())

    return {
        "org":         host.get("org", ""),
        "isp":         host.get("isp", ""),
        "country":     host.get("country_name", ""),
        "city":        host.get("city", ""),
        "open_ports":  open_ports,
        "banners":     banners,
        "vulns":       vulns,
        "last_update": host.get("last_update", ""),
        "hostnames":   host.get("hostnames", []),
    }
