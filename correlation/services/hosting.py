import re
import requests
from django.core.cache import cache

TIMEOUT = 5


def get_hosting_provider(ip: str) -> str:
    if not ip or ip == "UNRESOLVED":
        return "UNKNOWN"

    cache_key = f"hosting_{ip}"
    cached = cache.get(cache_key)
    if cached:
        return cached

    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=TIMEOUT)
        r.raise_for_status()
        org = r.json().get("org", "UNKNOWN")
        provider = re.sub(r"^AS\d+\s+", "", org).strip() or "UNKNOWN"
        cache.set(cache_key, provider, timeout=3600)
        return provider
    except Exception:
        return "UNKNOWN"
