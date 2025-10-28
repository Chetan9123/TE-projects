# incident_response/analyzer.py
"""
Analyze alerts, assign severity scores, and classify incident types.
"""

import json
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger("incident.analyzer")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def load_alerts(path: str, n: int = 200) -> List[Dict[str, Any]]:
    """Load recent alerts/actions from log file."""
    try:
        with open(path, "r", encoding="utf8") as f:
            lines = f.readlines()[-n:]
        return [json.loads(l) for l in lines if l.strip()]
    except Exception as e:
        logger.error("Failed to load alerts: %s", e)
        return []


def classify_severity(alert: Dict[str, Any]) -> str:
    """Simple heuristic severity classifier."""
    action = alert.get("action", "")
    msg = json.dumps(alert).lower()
    if "block_ip" in msg or "malicious" in msg:
        return "critical"
    elif "isolate" in msg or "quarantine" in msg:
        return "high"
    elif "alert" in msg or "deny" in msg:
        return "medium"
    else:
        return "low"


def analyze_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add severity and timestamp parsing."""
    analyzed = []
    for a in alerts:
        sev = classify_severity(a)
        a["severity"] = sev
        a["analyzed_at"] = datetime.utcnow().isoformat()
        analyzed.append(a)
    return analyzed
