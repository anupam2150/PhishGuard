from django.http import JsonResponse
from services.news import get_cyber_news


def news_feed(request):
    articles = get_cyber_news(page_size=15)
    data = [
        {
            "title": a.get("title", ""),
            "url":   a.get("url", "#"),
            "image": a.get("urlToImage", ""),
            "source": a.get("source", {}).get("name", ""),
            "date":  (a.get("publishedAt") or "")[:10],
            "desc":  (a.get("description") or "")[:120],
        }
        for a in articles
    ]
    return JsonResponse(data, safe=False)
