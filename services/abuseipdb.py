import requests
from django.core.cache import cache

BASE    = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 15
_TTL    = 7200   # 2 hours


def check_ip(ip: str, api_keys: dict = None) -> dict:
    api_keys  = api_keys or {}
    cache_key = f"abuseipdb_{ip}"

    cached = cache.get(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    try:
        r = requests.get(
            f"{BASE}/check",
            headers={"Key": api_keys.get("ABUSEIPDB_KEY", ""), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        result = r.json().get("data", {})
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    result["_cached"] = False
    cache.set(cache_key, result, _TTL)
    return result
