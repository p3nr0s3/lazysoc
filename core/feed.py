"""
Cyber Threat Intelligence RSS Feed Aggregator for LazySOC.
Fetches and caches live security advisories and news from top cybersecurity feeds.
"""

import time
import re
import requests
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import List, Dict, Any, Optional
from core.watchlist import match_text, priority_score, extract_cve_ids
from core.database import save_feed_articles, get_feed_article

FEED_SOURCES = {
    "thehackernews": {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "badge_color": "amber",
    },
    "bleepingcomputer": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "badge_color": "blue",
    },
    "cisa": {
        "name": "CISA Advisories",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "badge_color": "emerald",
    },
    "krebs": {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "badge_color": "purple",
    },
}

CACHE_TTL_SECONDS = 300  # 5 minutes cache
ITEMS_PER_FEED = 25
CONTENT_MAX_CHARS = 8000  # full text kept server-side for watchlist matching and AI summaries
RSS_CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}encoded"
_FEED_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "items": [],
}


def _strip_html(text: str, max_len: int = 280) -> str:
    """Removes HTML tags and cleans up whitespace."""
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"&[a-z]+;", " ", clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:max_len] + ("..." if len(clean) > max_len else "")


def _classify_category(title: str, summary: str) -> str:
    """Classifies news category based on title and summary content."""
    text = (title + " " + summary).lower()
    if any(k in text for k in ["0-day", "zero-day", "cve-", "vulnerability", "flaw", "rce", "bypass"]):
        return "Vulnerability"
    if any(k in text for k in ["ransomware", "extortion", "encryptor", "lockbit", "blackcat"]):
        return "Ransomware"
    if any(k in text for k in ["malware", "trojan", "infostealer", "backdoor", "c2", "stealer"]):
        return "Malware"
    if any(k in text for k in ["breach", "leak", "stolen", "database", "hack", "compromised"]):
        return "Data Breach"
    if any(k in text for k in ["cisa", "advisory", "alert", "warning", "patch", "update"]):
        return "Advisory"
    return "Cyber News"


def _published_at(pub_date: str) -> Optional[str]:
    """Normalizes RSS pubDate (RFC 822) or dc:date (ISO 8601) to UTC 'YYYY-MM-DD HH:MM:SS'."""
    if not pub_date:
        return None
    dt = None
    try:
        dt = parsedate_to_datetime(pub_date)
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(pub_date.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def fetch_single_feed(source_key: str, meta: Dict[str, str], timeout: int = 8) -> List[Dict[str, Any]]:
    """Fetches and parses a single RSS feed."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 LazySOC/3.0"
    }
    articles = []
    try:
        resp = requests.get(meta["url"], headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return []

        root = ET.fromstring(resp.content)
        items = root.findall(".//item")
        for item in items[:ITEMS_PER_FEED]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or item.findtext("{http://purl.org/dc/elements/1.1/}date") or "").strip()
            raw_desc = item.findtext("description") or ""
            summary = _strip_html(raw_desc)
            content = _strip_html(item.findtext(RSS_CONTENT_NS) or raw_desc, max_len=CONTENT_MAX_CHARS)

            if not title:
                continue

            category = _classify_category(title, summary)

            articles.append({
                "title": title,
                "link": link,
                "source": meta["name"],
                "source_key": source_key,
                "badge_color": meta["badge_color"],
                "pub_date": pub_date,
                "published_at": _published_at(pub_date),
                "summary": summary,
                "content": content,
                "category": category,
            })
    except Exception as e:
        # Graceful fallback per feed failure
        pass

    return articles


def _get_all_articles() -> List[Dict[str, Any]]:
    global _FEED_CACHE
    now = time.time()

    # Return cached results if still fresh
    if now - _FEED_CACHE["timestamp"] < CACHE_TTL_SECONDS and _FEED_CACHE["items"]:
        return _FEED_CACHE["items"]

    all_items = []
    for sk, meta in FEED_SOURCES.items():
        all_items.extend(fetch_single_feed(sk, meta))

    if all_items:
        all_items.sort(key=lambda a: a.get("published_at") or "", reverse=True)
        _FEED_CACHE["timestamp"] = now
        _FEED_CACHE["items"] = all_items
        try:
            save_feed_articles(all_items)  # history for period digests
        except Exception:
            pass
    return all_items or _FEED_CACHE["items"]


def refresh_feed_store() -> int:
    """Fetches the live feeds (if the cache is stale) so the article store is current."""
    return len(_get_all_articles())


def get_article_by_link(link: str) -> Optional[Dict[str, Any]]:
    """Finds a feed article (with its full text) by link, so callers can't submit arbitrary text."""
    live = next((a for a in _get_all_articles() if a.get("link") == link), None)
    return live or get_feed_article(link)


def _annotate(article: Dict[str, Any], owner: Optional[str]) -> Dict[str, Any]:
    text = f"{article['title']}\n{article.get('content') or article['summary']}"
    matches = match_text(text, owner=owner)
    public = {k: v for k, v in article.items() if k != "content"}
    public["watchlist_matches"] = matches
    public["watchlist_priority"] = priority_score(matches)
    public["cves"] = extract_cve_ids(text)
    return public


def get_cyber_news(source: str = "all", limit: int = 30, owner: Optional[str] = None, watchlist_only: bool = False) -> Dict[str, Any]:
    """Retrieves aggregated cyber news feeds, tagged with matching watchlist products."""
    now = time.time()
    all_items = _get_all_articles()

    # Filter by source if requested
    source = source.lower().strip()
    if source != "all" and source in FEED_SOURCES:
        filtered = [item for item in all_items if item["source_key"] == source]
    else:
        filtered = all_items

    owner = (owner or "").strip() or None
    annotated = [_annotate(a, owner) for a in filtered]
    if watchlist_only or owner:
        annotated = [a for a in annotated if a["watchlist_matches"]]
        annotated.sort(key=lambda a: a["watchlist_priority"], reverse=True)

    return {
        "total": len(annotated[:limit]),
        "sources": [s["name"] for s in FEED_SOURCES.values()],
        "cached": (now - _FEED_CACHE["timestamp"] < CACHE_TTL_SECONDS),
        "watchlist_matched": sum(1 for a in annotated if a["watchlist_matches"]),
        "items": annotated[:limit],
    }
