import math
import re
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account",
    "banking", "confirm", "signin", "wallet", "password",
]


class URLFeatureExtractor:
    def __init__(self, raw_url: str):
        self.raw_url = raw_url
        self._extracted = tldextract.extract(raw_url)

    def extract(self) -> dict:
        domain_full = self._extracted.registered_domain or self._extracted.domain
        subdomain = self._extracted.subdomain
        sld = self._extracted.domain
        tld = self._extracted.suffix

        is_ip_url = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self._extracted.domain))

        keywords_found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in self.raw_url.lower()]

        hyphen_count = domain_full.count("-")

        try:
            path = self.raw_url.split(domain_full, 1)[1] if domain_full in self.raw_url else ""
            path_depth = path.count("/")
        except Exception:
            path_depth = 0

        entropy = self._shannon_entropy(sld) if sld else 0.0

        tokens = re.split(r"[-.]", domain_full)
        fingerprint = sorted(set(t.lower() for t in tokens if t and t != tld))

        return {
            "domain": domain_full,
            "subdomain": subdomain,
            "sld": sld,
            "tld": tld,
            "is_ip_url": is_ip_url,
            "keywords_found": keywords_found,
            "hyphen_count": hyphen_count,
            "path_depth": path_depth,
            "entropy_score": round(entropy, 4),
            "structural_fingerprint": fingerprint,
        }

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((f / length) * math.log2(f / length) for f in freq.values())
