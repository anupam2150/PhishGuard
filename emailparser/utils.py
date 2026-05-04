import re
import email
from email import policy


LOOKALIKE_PATTERNS = re.compile(r"paypa[l1]|g[o0]{2}gle|arnazon|micros0ft|app[l1]e|faceb[o0]{2}k", re.I)


def _extract_domain(address: str) -> str:
    match = re.search(r"@([\w.\-]+)", address or "")
    return match.group(1).lower() if match else ""


def _parse_auth(auth_results: str) -> tuple[str, str, str]:
    def find(key):
        m = re.search(rf"{key}=(\w+)", auth_results or "", re.I)
        return m.group(1).lower() if m else "none"
    return find("spf"), find("dkim"), find("dmarc")


def parse_headers(raw_headers: str) -> dict:
    msg = email.message_from_string(raw_headers, policy=policy.compat32)

    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "") or None
    return_path = msg.get("Return-Path", "") or None
    x_mailer = msg.get("X-Mailer", "") or None
    auth_results = msg.get("Authentication-Results", "")

    received = msg.get_all("Received") or []
    hop_count = len(received)

    spf, dkim, dmarc = _parse_auth(auth_results)

    flags = []
    if spf == "fail":
        flags.append("SPF fail")
    if dkim == "none":
        flags.append("DKIM missing")
    if dmarc == "fail":
        flags.append("DMARC fail")

    from_domain = _extract_domain(sender)
    rt_domain = _extract_domain(reply_to or "")
    if reply_to and rt_domain and rt_domain != from_domain:
        flags.append("Reply-To mismatch")

    if LOOKALIKE_PATTERNS.search(from_domain):
        flags.append("Lookalike domain")

    if hop_count > 8:
        flags.append("Excessive hops")

    if not x_mailer or x_mailer.strip().lower() in ("", "unknown"):
        flags.append("Unknown mailer")

    flag_count = len(flags)
    if flag_count >= 3:
        risk_level = "HIGH"
    elif flag_count >= 1:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "x_mailer": x_mailer,
        "hop_count": hop_count,
        "suspicious_flags": flags,
        "risk_level": risk_level,
    }
