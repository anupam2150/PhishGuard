import os
import requests

BASE = "https://api.abuseipdb.com/api/v2"
TIMEOUT = 15


def check_ip(ip: str) -> dict:
    try:
        r = requests.get(
            f"{BASE}/check",
            headers={"Key": os.getenv("ABUSEIPDB_KEY", ""), "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        return r.json().get("data", {})
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}
