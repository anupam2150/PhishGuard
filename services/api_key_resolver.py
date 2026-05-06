import os


def get_api_keys(user) -> dict:
    """
    Return API keys for the given user.
    Per-user keys from UserProfile take priority; falls back to .env values.
    Works for anonymous users too — always returns a complete dict.
    """
    keys = {
        "VT_API_KEY":    os.getenv("VT_API_KEY", ""),
        "ABUSEIPDB_KEY": os.getenv("ABUSEIPDB_KEY", ""),
        "GSB_API_KEY":   os.getenv("GSB_API_KEY", ""),
    }

    if not (user and user.is_authenticated):
        return keys

    try:
        profile = user.profile
        if profile.vt_api_key:
            keys["VT_API_KEY"] = profile.vt_api_key
        if profile.abuseipdb_key:
            keys["ABUSEIPDB_KEY"] = profile.abuseipdb_key
        if profile.gsb_api_key:
            keys["GSB_API_KEY"] = profile.gsb_api_key
    except Exception:
        pass  # profile missing — use env fallbacks

    return keys
