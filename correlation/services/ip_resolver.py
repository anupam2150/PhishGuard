import socket

_cache: dict = {}


def resolve_ip(domain: str) -> str:
    if domain in _cache:
        return _cache[domain]
    try:
        socket.setdefaulttimeout(3)
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        ip = results[0][4][0]
        _cache[domain] = ip
        return ip
    except Exception:
        _cache[domain] = "UNRESOLVED"
        return "UNRESOLVED"


def get_subnet(ip: str) -> str:
    if not ip or ip == "UNRESOLVED":
        return ""
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return ""
