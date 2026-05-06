import base64
import hashlib
import requests
from django.core.cache import cache

BASE    = "https://www.virustotal.com/api/v3"
TIMEOUT = 15
_TTL    = 3600   # 1 hour


def _cache_key(indicator: str) -> str:
    return f"vt_{hashlib.md5(indicator.encode()).hexdigest()}"


def _get(endpoint: str, api_keys: dict, cache_key: str) -> dict:
    cached = cache.get(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    headers = {"x-apikey": api_keys.get("VT_API_KEY", "")}
    try:
        r = requests.get(f"{BASE}{endpoint}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 429:
            return {"error": "VirusTotal rate limit reached. Please wait and retry."}
        r.raise_for_status()
        result = r.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

    result["_cached"] = False
    cache.set(cache_key, result, _TTL)
    return result


def scan_url(url: str, api_keys: dict = None) -> dict:
    api_keys = api_keys or {}
    url_id   = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return _get(f"/urls/{url_id}", api_keys, _cache_key(url))


def scan_domain(domain: str, api_keys: dict = None) -> dict:
    return _get(f"/domains/{domain}", api_keys or {}, _cache_key(domain))


def scan_ip(ip: str, api_keys: dict = None) -> dict:
    return _get(f"/ip_addresses/{ip}", api_keys or {}, _cache_key(ip))


def scan_hash(file_hash: str, api_keys: dict = None) -> dict:
    return _get(f"/files/{file_hash}", api_keys or {}, _cache_key(file_hash))
