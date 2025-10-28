# threat_intelligence/feed_fetcher.py
"""
Fetch threat intelligence from public APIs and feeds.
(Offline-friendly fallback with mock data.)
"""

import json
import os
import logging
import requests
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger("threat.feed_fetcher")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


CACHE_PATH = "threat_intelligence/cache/latest_feed.json"

PUBLIC_FEEDS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.json",  # botnet C2 IPs
    "https://urlhaus.abuse.ch/downloads/json/",                  # malicious URLs
]


def fetch_from_feed(url: str) -> List[Dict[str, Any]]:
    """Fetch JSON or text feed."""
    try:
        logger.info("Fetching threat feed: %s", url)
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            try:
                data = r.json()
                return data.get("data") or data.get("urls") or data.get("ips") or data
            except Exception:
                # fallback for plain text feeds
                return [{"raw": line} for line in r.text.splitlines() if line.strip()]
        else:
            logger.warning("Feed %s returned %d", url, r.status_code)
            return []
    except Exception as e:
        logger.error("Failed to fetch %s: %s", url, e)
        return []


def fetch_all_feeds() -> List[Dict[str, Any]]:
    """Fetch from all configured feeds."""
    all_items = []
    for f in PUBLIC_FEEDS:
        all_items.extend(fetch_from_feed(f))
    os.makedirs(os.path.dirname(CACHE_PATH) or ".", exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf8") as f:
        json.dump(all_items, f, indent=2)
    logger.info("Saved %d items to cache", len(all_items))
    return all_items
