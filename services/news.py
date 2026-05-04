import os
import requests

NEWS_API_KEY = os.getenv("NEWS_API_KEY", "")
BASE = "https://newsapi.org/v2/everything"
TIMEOUT = 10

EXCLUDE_WORDS = {
    "politics", "political", "election", "sports", "football", "basketball",
    "soccer", "tennis", "cricket", "entertainment", "celebrity", "hollywood",
    "music", "movie", "film", "tv show", "reality show", "gossip",
}


def _is_relevant(article: dict) -> bool:
    title = (article.get("title") or "").lower()
    if title == "[removed]":
        return False
    return not any(word in title for word in EXCLUDE_WORDS)


def get_cyber_news(page_size: int = 15) -> list:
    if not NEWS_API_KEY:
        return []
    try:
        r = requests.get(
            BASE,
            params={
                "q": "cybersecurity OR phishing OR malware OR ransomware OR CVE OR data breach",
                "language": "en",
                "sortBy": "publishedAt",
                "pageSize": page_size,
                "apiKey": NEWS_API_KEY,
            },
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        articles = r.json().get("articles", [])
        return [a for a in articles if _is_relevant(a)]
    except requests.exceptions.RequestException:
        return []
