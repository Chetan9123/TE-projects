# threat_intelligence/parser.py
"""
Normalize and extract IPs/domains/URLs from raw threat feed data.
"""

import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger("threat.parser")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def extract_ips(raw_items: List[Dict[str, Any]]) -> List[str]:
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    ips = []
    for i in raw_items:
        text = str(i)
        ips.extend(ip_pattern.findall(text))
    unique = sorted(set(ips))
    logger.info("Extracted %d unique IPs", len(unique))
    return unique


def extract_domains(raw_items: List[Dict[str, Any]]) -> List[str]:
    domain_pattern = re.compile(r"\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
    doms = []
    for i in raw_items:
        text = str(i)
        doms.extend(domain_pattern.findall(text))
    unique = sorted(set(doms))
    logger.info("Extracted %d unique domains", len(unique))
    return unique


def parse_feed_data(raw_items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    return {
        "ips": extract_ips(raw_items),
        "domains": extract_domains(raw_items),
    }
