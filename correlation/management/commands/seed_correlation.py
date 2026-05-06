from django.core.management.base import BaseCommand
from correlation.models import CampaignScan, URLRecord, Campaign
from correlation.services.url_parser import URLFeatureExtractor
from correlation.services.ip_resolver import resolve_ip, get_subnet
from correlation.services.hosting import get_hosting_provider
from correlation.services.correlator import CampaignCorrelator
from correlation.services.confidence import ConfidenceScorer

TEST_URLS = [
    "https://paypal-secure-login.com/verify",
    "https://paypal-account-update.net/signin",
    "https://secure-paypal-confirm.xyz/login",
    "https://paypal-wallet-verify.top/account",
    "https://paypal-login-secure.ml/update",
    "https://bankofamerica-login.xyz/secure",
    "https://chase-account-verify.top/signin",
    "https://wellsfargo-secure-login.ml/confirm",
    "https://citibank-update-account.ga/login",
    "https://hsbc-banking-verify.cf/account",
    "https://metamask-wallet-login.com/connect",
    "https://coinbase-verify-wallet.net/signin",
    "https://binance-secure-account.xyz/login",
    "https://example.com/page",
    "https://github.com/login",
]


class Command(BaseCommand):
    help = "Seed correlation app with test campaign data"

    def handle(self, *args, **kwargs):
        self.stdout.write("Creating test campaign scan...")

        scan = CampaignScan.objects.create(
            scan_label="Test Seed - 3 Campaigns",
            total_urls=len(TEST_URLS),
            status="PROCESSING",
        )

        scorer = ConfidenceScorer()
        url_dicts = []

        for raw_url in TEST_URLS:
            features = URLFeatureExtractor(raw_url).extract()
            ip = resolve_ip(features["domain"])
            subnet = get_subnet(ip)
            provider = get_hosting_provider(ip)
            individual = scorer.score_individual(features)

            url_dicts.append({
                "raw_url": raw_url,
                "domain": features["domain"],
                "ip_address": ip,
                "subnet": subnet,
                "hosting_provider": provider,
                "keywords_found": features["keywords_found"],
                "structural_fingerprint": features["structural_fingerprint"],
                "entropy_score": features["entropy_score"],
                "suspicion_score": individual["score"],
                "suspicion_label": individual["label"],
                "tld": features.get("tld", ""),
                "hyphen_count": features.get("hyphen_count", 0),
                "is_ip_url": features.get("is_ip_url", False),
                "path_depth": features.get("path_depth", 0),
            })

        records = URLRecord.objects.bulk_create([
            URLRecord(
                scan=scan,
                raw_url=d["raw_url"], domain=d["domain"],
                ip_address=d["ip_address"], subnet=d["subnet"],
                hosting_provider=d["hosting_provider"],
                keywords_found=d["keywords_found"],
                structural_fingerprint=d["structural_fingerprint"],
                entropy_score=d["entropy_score"],
                suspicion_score=d["suspicion_score"],
                suspicion_label=d["suspicion_label"],
            ) for d in url_dicts
        ])

        record_map = {r.raw_url: r for r in records}
        clusters = CampaignCorrelator(url_dicts).correlate()

        self.stdout.write(f"\nFound {len(clusters)} campaign cluster(s):\n")

        for idx, cluster in enumerate(clusters):
            c_score = scorer.score(cluster)
            c_label = scorer.score_label(c_score)
            reasons = CampaignCorrelator.explain_cluster(cluster)

            ips = [u["ip_address"] for u in cluster if u.get("ip_address") and u["ip_address"] != "UNRESOLVED"]
            shared_ip = ips[0] if len(set(ips)) == 1 and ips else None
            providers = [u["hosting_provider"] for u in cluster if u.get("hosting_provider") and u["hosting_provider"] != "UNKNOWN"]
            shared_prov = providers[0] if len(set(providers)) == 1 and providers else None

            campaign = Campaign.objects.create(
                scan=scan, campaign_index=idx + 1,
                url_count=len(cluster), confidence_score=c_score,
                confidence_label=c_label, shared_ip=shared_ip,
                shared_provider=shared_prov, reasons=reasons,
            )
            campaign.urls.set([record_map[u["raw_url"]] for u in cluster if u["raw_url"] in record_map])

            self.stdout.write(f"  Campaign #{idx+1}: {len(cluster)} URLs | {c_label} ({c_score})")
            for r in reasons:
                self.stdout.write(f"    - {r}")

        scan.total_campaigns = len(clusters)
        scan.status = "COMPLETE"
        scan.save()

        self.stdout.write(self.style.SUCCESS(f"\nDone. Scan ID: {scan.pk}"))
        self.stdout.write(f"View at: http://127.0.0.1:8000/correlation/results/{scan.pk}/")
