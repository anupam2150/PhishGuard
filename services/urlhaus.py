"""
URLhaus threat feed integration (abuse.ch).
No API key required. Free public API.
https://urlhaus-api.abuse.ch/
Results cached 2 hours per indicator.
"""

import hashlib
import requests
from django.core.cache import cache

_TIMEOUT   = 5
_TTL       = 7200   # 2 hours
_URL_EP    = "https://urlhaus-api.abuse.ch/v1/url/"
_HOST_EP   = "https://urlhaus-api.abuse.ch/v1/host/"
_NOT_FOUND = {"found": False}


def _cache_key(indicator: str) -> str:
    return f"urlhaus_{hashlib.md5(indicator.encode()).hexdigest()}"


def check_urlhaus(indicator: str) -> dict:
    """
    Query URLhaus for a URL, domain, or IP address.
    Returns {"found": False} on any failure or timeout.
    """
    indicator = indicator.strip()
    if not indicator:
        return _NOT_FOUND

    cache_key = _cache_key(indicator)
    cached    = cache.get(cache_key)
    if cached is not None:
        result = dict(cached)
        result["_cached"] = True
        return result

    is_url = indicator.startswith("http://") or indicator.startswith("https://")

    try:
        if is_url:
            resp = requests.post(_URL_EP, data={"url": indicator}, timeout=_TIMEOUT)
        else:
            resp = requests.post(_HOST_EP, data={"host": indicator}, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException:
        return _NOT_FOUND

    query_status = data.get("query_status", "")
    if query_status in ("no_results", "not_found") or not data:
        result = dict(_NOT_FOUND)
    elif is_url:
        result = _parse_url_response(data)
    else:
        result = _parse_host_response(data)

    result["_cached"] = False
    cache.set(cache_key, result, _TTL)
    return result


def _parse_url_response(data: dict) -> dict:
    tags = []
    for t in (data.get("tags") or []):
        if isinstance(t, str):
            tags.append(t)
        elif isinstance(t, dict):
            tags.append(t.get("tag", ""))
    return {
        "found":      True,
        "status":     data.get("url_status", "unknown"),
        "threat":     data.get("threat", ""),
        "tags":       [t for t in tags if t],
        "url_count":  1,
        "date_added": data.get("date_added", ""),
    }


def _parse_host_response(data: dict) -> dict:
    urls      = data.get("urls") or []
    threats, tags = set(), set()
    for u in urls:
        if u.get("threat"):
            threats.add(u["threat"])
        for t in (u.get("tags") or []):
            tag = t if isinstance(t, str) else t.get("tag", "")
            if tag:
                tags.add(tag)
    statuses = {u.get("url_status", "unknown") for u in urls}
    status   = "online" if "online" in statuses else ("offline" if "offline" in statuses else "unknown")
    return {
        "found":      True,
        "status":     status,
        "threat":     ", ".join(sorted(threats)) if threats else "",
        "tags":       sorted(tags),
        "url_count":  len(urls),
        "date_added": urls[0].get("date_added", "") if urls else "",
    }
