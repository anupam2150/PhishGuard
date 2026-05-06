"""
SSL/TLS certificate analysis service.
Uses Python's built-in ssl + socket modules and the cryptography library.
No external API or key required.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtensionOID, NameOID

logger = logging.getLogger(__name__)

_TIMEOUT = 5
_PORT    = 443


def analyze_ssl(domain: str) -> dict:
    """
    Connect to domain:443, retrieve and parse the TLS certificate.

    Returns a dict with all certificate fields and a computed
    'ssl_risk_flags' list.  Returns {'error': str, 'ssl_available': False}
    on any connection or parse failure.
    """
    # Strip port if caller passed host:port
    host = domain.split(":")[0]

    try:
        der = _fetch_cert_der(host)
    except Exception as exc:
        logger.debug("SSL connect failed for %s: %s", host, exc)
        return {"error": str(exc), "ssl_available": False}

    try:
        return _parse_cert(der, host)
    except Exception as exc:
        logger.warning("SSL parse failed for %s: %s", host, exc)
        return {"error": f"Certificate parse error: {exc}", "ssl_available": False}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fetch_cert_der(host: str) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED

    with socket.create_connection((host, _PORT), timeout=_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _cn(name) -> str:
    """Extract the Common Name from an x509 Name, or return empty string."""
    try:
        return name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        return ""


def _parse_cert(der: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    now  = datetime.now(timezone.utc)

    # Validity window
    valid_from  = cert.not_valid_before_utc
    valid_until = cert.not_valid_after_utc
    days_remaining   = (valid_until - now).days
    is_recently_issued = (now - valid_from).days < 30

    # Subject / Issuer
    subject_cn = _cn(cert.subject)
    issuer_cn  = _cn(cert.issuer)
    is_self_signed = (cert.subject == cert.issuer)

    # Subject Alternative Names
    san_domains = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_domains = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    has_wildcard_san = any(s.startswith("*.") for s in san_domains)

    # Signature algorithm
    try:
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    except Exception:
        sig_algo = "unknown"

    # ── Risk flags ────────────────────────────────────────────────────────────
    flags = []
    if is_self_signed:
        flags.append("Self-signed certificate")
    if is_recently_issued:
        flags.append("Certificate issued < 30 days ago")
    if has_wildcard_san and len(san_domains) > 10:
        flags.append("Wildcard SAN abuse possible")
    if days_remaining < 0:
        flags.append("Certificate already expired")
    elif days_remaining < 7:
        flags.append("Certificate expires in < 7 days")

    return {
        "ssl_available":      True,
        "subject":            subject_cn,
        "issuer":             issuer_cn,
        "valid_from":         valid_from.isoformat(),
        "valid_until":        valid_until.isoformat(),
        "days_remaining":     days_remaining,
        "is_self_signed":     is_self_signed,
        "is_recently_issued": is_recently_issued,
        "san_domains":        list(san_domains),
        "has_wildcard_san":   has_wildcard_san,
        "signature_algorithm": sig_algo,
        "ssl_risk_flags":     flags,
    }
