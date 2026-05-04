import os
import requests

BASE = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 15


def check_url(url: str) -> bool:
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(BASE, params={"key": os.getenv("GSB_API_KEY", "")}, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        return bool(r.json().get("matches"))
    except requests.exceptions.RequestException:
        return False
