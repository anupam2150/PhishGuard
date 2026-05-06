from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator
from django.contrib import messages
from django_ratelimit.decorators import ratelimit
import json

from .forms import CampaignScanForm
from .models import CampaignScan, URLRecord, Campaign
from .services.url_parser import URLFeatureExtractor
from .services.ip_resolver import resolve_ip, get_subnet
from .services.hosting import get_hosting_provider
from .services.correlator import CampaignCorrelator
from .services.confidence import ConfidenceScorer


@ratelimit(key="user_or_ip", rate="10/h", method="POST", block=True)
def index(request):
    form = CampaignScanForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        urls = form.cleaned_data["url_input"]
        label = form.cleaned_data.get("scan_label", "")
        scan = CampaignScan.objects.create(
            user=request.user if request.user.is_authenticated else None,
            scan_label=label,
            total_urls=len(urls),
            status="PENDING",
        )
        request.session[f"scan_urls_{scan.pk}"] = urls
        return redirect("correlation:correlation_process", scan_id=scan.pk)

    qs = CampaignScan.objects.order_by("-submitted_at")
    if request.user.is_authenticated:
        recent = qs.filter(user=request.user)[:5]
    else:
        recent = qs.filter(user=None)[:5]
    return render(request, "correlation/index.html", {"form": form, "recent_scans": recent})


def process_scan(request, scan_id):
    scan = get_object_or_404(CampaignScan, pk=scan_id)
    urls = request.session.pop(f"scan_urls_{scan_id}", [])

    if not urls:
        messages.error(request, "No URLs found for this scan.")
        return redirect("correlation:correlation_index")

    try:
        scan.status = "PROCESSING"
        scan.save()

        scorer = ConfidenceScorer()
        url_dicts = []

        for raw_url in urls:
            features = URLFeatureExtractor(raw_url).extract()
            ip = resolve_ip(features["domain"])
            subnet = get_subnet(ip)
            provider = get_hosting_provider(ip)
            individual = scorer.score_individual({**features})

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
                raw_url=d["raw_url"],
                domain=d["domain"],
                ip_address=d["ip_address"],
                subnet=d["subnet"],
                hosting_provider=d["hosting_provider"],
                keywords_found=d["keywords_found"],
                structural_fingerprint=d["structural_fingerprint"],
                entropy_score=d["entropy_score"],
                suspicion_score=d["suspicion_score"],
                suspicion_label=d["suspicion_label"],
            )
            for d in url_dicts
        ])

        record_map = {r.raw_url: r for r in records}
        clusters = CampaignCorrelator(url_dicts).correlate()

        for idx, cluster in enumerate(clusters):
            c_score = scorer.score(cluster)
            c_label = scorer.score_label(c_score)
            reasons = CampaignCorrelator.explain_cluster(cluster)

            ips = [u["ip_address"] for u in cluster if u.get("ip_address") and u["ip_address"] != "UNRESOLVED"]
            shared_ip = ips[0] if len(set(ips)) == 1 and ips else None

            providers = [u["hosting_provider"] for u in cluster if u.get("hosting_provider") and u["hosting_provider"] != "UNKNOWN"]
            shared_prov = providers[0] if len(set(providers)) == 1 and providers else None

            campaign = Campaign.objects.create(
                scan=scan,
                campaign_index=idx + 1,
                url_count=len(cluster),
                confidence_score=c_score,
                confidence_label=c_label,
                shared_ip=shared_ip,
                shared_provider=shared_prov,
                reasons=reasons,
            )
            campaign.urls.set([record_map[u["raw_url"]] for u in cluster if u["raw_url"] in record_map])

        scan.total_campaigns = len(clusters)
        scan.status = "COMPLETE"
        scan.save()

    except Exception as e:
        scan.status = "FAILED"
        scan.save()
        messages.error(request, f"Processing failed: {e}")
        return redirect("correlation:correlation_index")

    return redirect("correlation:correlation_results", scan_id=scan.pk)


def results(request, scan_id):
    scan = get_object_or_404(CampaignScan, pk=scan_id)
    campaigns = scan.campaigns.prefetch_related("urls").order_by("-confidence_score")

    nodes, links, node_ids = [], [], {}

    def get_node(label, group):
        if label not in node_ids:
            node_ids[label] = len(nodes)
            nodes.append({"id": len(nodes), "label": label, "group": group})
        return node_ids[label]

    for c in campaigns:
        for url in c.urls.all():
            d_id = get_node(url.domain, "domain")
            if url.ip_address and url.ip_address != "UNRESOLVED":
                ip_id = get_node(url.ip_address, "ip")
                links.append({"source": d_id, "target": ip_id})
            if url.hosting_provider and url.hosting_provider != "UNKNOWN":
                h_id = get_node(url.hosting_provider, "hosting")
                links.append({"source": d_id, "target": h_id})

    graph_data = json.dumps({"nodes": nodes, "links": links})
    highest = campaigns[0].confidence_score if campaigns else 0

    return render(request, "correlation/results.html", {
        "scan": scan,
        "campaigns": campaigns,
        "graph_data": graph_data,
        "highest_confidence": highest,
    })


def campaign_detail(request, scan_id, campaign_index):
    scan = get_object_or_404(CampaignScan, pk=scan_id)
    campaign = get_object_or_404(Campaign, scan=scan, campaign_index=campaign_index)
    urls = campaign.urls.all()

    nodes, links, node_ids = [], [], {}

    def get_node(label, group):
        if label not in node_ids:
            node_ids[label] = len(nodes)
            nodes.append({"id": len(nodes), "label": label, "group": group})
        return node_ids[label]

    for url in urls:
        d_id = get_node(url.domain, "domain")
        if url.ip_address and url.ip_address != "UNRESOLVED":
            ip_id = get_node(url.ip_address, "ip")
            links.append({"source": d_id, "target": ip_id})
        if url.hosting_provider and url.hosting_provider != "UNKNOWN":
            h_id = get_node(url.hosting_provider, "hosting")
            links.append({"source": d_id, "target": h_id})

    graph_data = json.dumps({"nodes": nodes, "links": links})

    return render(request, "correlation/campaign_detail.html", {
        "scan": scan,
        "campaign": campaign,
        "urls": urls,
        "graph_data": graph_data,
    })


def scan_history(request):
    qs = CampaignScan.objects.order_by("-submitted_at")
    if request.user.is_authenticated:
        qs = qs.filter(user=request.user)
    else:
        qs = qs.filter(user=None)
    paginator = Paginator(qs, 10)
    page = paginator.get_page(request.GET.get("page"))
    return render(request, "correlation/history.html", {"page_obj": page})
