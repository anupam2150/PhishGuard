from collections import Counter

SKIP_PROVIDERS = {"UNKNOWN", "Cloudflare", "Fastly", "Akamai"}


class CampaignCorrelator:
    def __init__(self, url_dicts: list):
        self.urls = url_dicts
        self.n = len(url_dicts)
        self.parent = list(range(self.n))
        self.rank = [0] * self.n

    def _find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def _union(self, x, y):
        rx, ry = self._find(x), self._find(y)
        if rx == ry:
            return
        if self.rank[rx] < self.rank[ry]:
            rx, ry = ry, rx
        self.parent[ry] = rx
        if self.rank[rx] == self.rank[ry]:
            self.rank[rx] += 1

    def _jaccard(self, a: list, b: list) -> float:
        sa, sb = set(a), set(b)
        if not sa and not sb:
            return 0.0
        return len(sa & sb) / len(sa | sb)

    def correlate(self) -> list:
        for i in range(self.n):
            for j in range(i + 1, self.n):
                weight = 0
                a, b = self.urls[i], self.urls[j]

                if a.get("ip_address") and a["ip_address"] == b.get("ip_address") and a["ip_address"] != "UNRESOLVED":
                    weight += 3
                elif a.get("subnet") and a["subnet"] == b.get("subnet") and a["subnet"]:
                    weight += 2

                prov_a = a.get("hosting_provider", "UNKNOWN")
                prov_b = b.get("hosting_provider", "UNKNOWN")
                if prov_a not in SKIP_PROVIDERS and prov_a == prov_b:
                    weight += 1

                fp_sim = self._jaccard(a.get("structural_fingerprint", []), b.get("structural_fingerprint", []))
                if fp_sim > 0.4:
                    weight += 2

                shared_kw = set(a.get("keywords_found", [])) & set(b.get("keywords_found", []))
                if len(shared_kw) >= 2:
                    weight += 1

                if weight >= 3:
                    self._union(i, j)

        clusters: dict = {}
        for i in range(self.n):
            root = self._find(i)
            clusters.setdefault(root, []).append(self.urls[i])

        return list(clusters.values())

    @staticmethod
    def explain_cluster(url_list: list) -> list:
        reasons = []

        ip_counts = Counter(u.get("ip_address") for u in url_list if u.get("ip_address") and u["ip_address"] != "UNRESOLVED")
        for ip, count in ip_counts.most_common(1):
            if count > 1:
                reasons.append(f"Shared IP address: {ip} ({count} URLs)")

        provider_counts = Counter(u.get("hosting_provider") for u in url_list if u.get("hosting_provider") and u["hosting_provider"] not in SKIP_PROVIDERS)
        for prov, count in provider_counts.most_common(1):
            if count > 1:
                reasons.append(f"Shared hosting provider: {prov} ({count} URLs)")

        all_tokens = []
        for u in url_list:
            all_tokens.extend(u.get("structural_fingerprint", []))
        common_tokens = [t for t, c in Counter(all_tokens).most_common(5) if c > 1]
        if common_tokens:
            reasons.append(f"Similar domain pattern: {common_tokens} ({len(url_list)} URLs)")

        all_kw = []
        for u in url_list:
            all_kw.extend(u.get("keywords_found", []))
        common_kw = [k for k, c in Counter(all_kw).most_common(3) if c > 1]
        if common_kw:
            reasons.append(f"Shared suspicious keywords: {common_kw} ({len(url_list)} URLs)")

        return reasons
