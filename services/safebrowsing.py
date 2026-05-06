import hashlib
import requests
from django.core.cache import cache

BASE    = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 15
_TTL    = 1800   # 30 minutes


def check_url(url: str, api_keys: dict = None) -> bool:
    api_keys  = api_keys or {}
    cache_key = f"gsb_{hashlib.md5(url.encode()).hexdigest()}"

    cached = cache.get(cache_key)
    if cached is not None:
        # Stored as {"flagged": bool, "_cached": True}
        return cached.get("flagged", False)

    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }
    try:
        r = requests.post(BASE, params={"key": api_keys.get("GSB_API_KEY", "")}, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        flagged = bool(r.json().get("matches"))
    except requests.exceptions.RequestException:
        return False

    cache.set(cache_key, {"flagged": flagged, "_cached": False}, _TTL)
    return flagged
