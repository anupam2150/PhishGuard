import os
import base64
import requests

BASE = "https://www.virustotal.com/api/v3"
TIMEOUT = 15


def _get(endpoint: str) -> dict:
    headers = {"x-apikey": os.getenv("VT_API_KEY", "")}
    try:
        r = requests.get(f"{BASE}{endpoint}", headers=headers, timeout=TIMEOUT)
        if r.status_code == 429:
            return {"error": "VirusTotal rate limit reached. Please wait and retry."}
        r.raise_for_status()
        return r.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def scan_url(url: str) -> dict:
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    return _get(f"/urls/{url_id}")


def scan_domain(domain: str) -> dict:
    return _get(f"/domains/{domain}")


def scan_ip(ip: str) -> dict:
    return _get(f"/ip_addresses/{ip}")


def scan_hash(file_hash: str) -> dict:
    return _get(f"/files/{file_hash}")
