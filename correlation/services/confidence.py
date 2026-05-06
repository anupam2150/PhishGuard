HIGH_RISK_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".club"}


class ConfidenceScorer:

    def score(self, url_list: list) -> float:
        if not url_list:
            return 0.0
        total = 0.0

        ips = [u.get("ip_address") for u in url_list if u.get("ip_address") and u["ip_address"] != "UNRESOLVED"]
        if len(set(ips)) == 1 and ips:
            total += 0.30
        elif len(set(u.get("subnet", "") for u in url_list if u.get("subnet"))) == 1:
            total += 0.15

        providers = [u.get("hosting_provider") for u in url_list if u.get("hosting_provider") and u["hosting_provider"] != "UNKNOWN"]
        if providers and len(set(providers)) == 1:
            total += 0.15

        fps = [u.get("structural_fingerprint", []) for u in url_list]
        if len(fps) >= 2:
            sims = []
            for i in range(len(fps)):
                for j in range(i + 1, len(fps)):
                    sa, sb = set(fps[i]), set(fps[j])
                    if sa | sb:
                        sims.append(len(sa & sb) / len(sa | sb))
            if sims and (sum(sims) / len(sims)) > 0.4:
                total += 0.20

        all_kw = []
        for u in url_list:
            all_kw.extend(u.get("keywords_found", []))
        from collections import Counter
        if any(c >= 2 for c in Counter(all_kw).values()):
            total += 0.10

        if len(url_list) >= 5:
            total += 0.05

        return min(round(total, 4), 1.0)

    def score_label(self, score: float) -> str:
        if score >= 0.75:
            return "HIGH"
        if score >= 0.50:
            return "MEDIUM"
        return "LOW CONFIDENCE"

    def score_individual(self, url_dict: dict) -> dict:
        score = 0.0
        signals = []

        if len(url_dict.get("keywords_found", [])) >= 2:
            score += 0.25
            signals.append("2+ suspicious keywords")

        if url_dict.get("hyphen_count", 0) >= 3:
            score += 0.15
            signals.append("3+ hyphens in domain")

        if (url_dict.get("entropy_score") or 0) > 3.5:
            score += 0.20
            signals.append("High entropy domain")

        if url_dict.get("is_ip_url"):
            score += 0.20
            signals.append("IP-based URL")

        tld = "." + url_dict.get("tld", "")
        if tld in HIGH_RISK_TLDS:
            score += 0.15
            signals.append(f"High-risk TLD ({tld})")

        if url_dict.get("path_depth", 0) > 4:
            score += 0.05
            signals.append("Deep URL path")

        score = min(round(score, 4), 1.0)
        label = "HIGH" if score >= 0.6 else "MEDIUM" if score >= 0.3 else "LOW"

        return {"score": score, "label": label, "triggered_signals": signals}
