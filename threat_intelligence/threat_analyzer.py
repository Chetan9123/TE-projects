# threat_intelligence/threat_analyzer.py
"""
Optionally perform ML-based scoring or correlation of threat intel data.
"""

import hashlib
import random
import logging
from typing import List, Dict, Any

logger = logging.getLogger("threat.analyzer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def score_ip(ip: str) -> float:
    """Generate a deterministic pseudo score (0–1) for demo."""
    digest = hashlib.sha256(ip.encode()).hexdigest()
    seed = int(digest[:8], 16)
    random.seed(seed)
    return round(random.uniform(0, 1), 3)


def analyze_threats(parsed_data: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Assign threat scores to IPs/domains."""
    results = []
    for ip in parsed_data.get("ips", []):
        results.append({"indicator": ip, "type": "ip", "score": score_ip(ip)})
    for dom in parsed_data.get("domains", []):
        results.append({"indicator": dom, "type": "domain", "score": score_ip(dom)})
    logger.info("Analyzed %d indicators", len(results))
    return sorted(results, key=lambda x: x["score"], reverse=True)
