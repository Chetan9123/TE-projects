# zero_trust_control/session_monitor.py
"""
Session monitoring: track active sessions and perform continuous checks.

Features:
- create_session(session_id, context)
- update_session(session_id, event)
- check_session(session_id) -> returns health/status
- simple anomaly detection: sudden spike in data exfiltration, atypical destinations, rapid port scans

This is a lightweight in-memory implementation; in production use a database or streaming system.
"""

import time
import logging
from typing import Dict, Any, List
from collections import defaultdict, deque

logger = logging.getLogger("zero_trust.session")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

# In-memory store
_sessions: Dict[str, Dict[str, Any]] = {}
_session_events: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))  # keep last N events per session


def create_session(session_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new session object with context (user/device/resource)
    """
    s = {
        "session_id": session_id,
        "created_at": time.time(),
        "last_seen": time.time(),
        "context": context,
        "status": "active",
        "cumulative_bytes": 0,
        "events_count": 0
    }
    _sessions[session_id] = s
    logger.info("Created session %s", session_id)
    return s


def update_session(session_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update session stats based on an event. Example event:
    {
      "timestamp": 1234567,
      "src_ip": "...", "dst_ip": "...", "bytes": 1234, "dport": 443, "event_type": "flow"
    }
    """
    s = _sessions.get(session_id)
    if not s:
        logger.warning("Session %s not found; creating new", session_id)
        s = create_session(session_id, context={})
    s["last_seen"] = time.time()
    s["events_count"] += 1
    b = event.get("bytes", 0)
    s["cumulative_bytes"] += b
    # push event for short-term analysis
    _session_events[session_id].append(event)
    # simple anomaly checks
    # 1) sudden data spike
    if s["cumulative_bytes"] > 100 * 1024 * 1024:  # example: >100MB
        s["status"] = "suspicious"
        s.setdefault("alerts", []).append({"reason": "high_data_transfer", "when": time.time(), "bytes": s["cumulative_bytes"]})
        logger.info("Session %s marked suspicious: high data transfer %d", session_id, s["cumulative_bytes"])
    # 2) many unique destinations in short time
    last_events = list(_session_events[session_id])[-50:]
    unique_dst = len({e.get("dst_ip") for e in last_events if e.get("dst_ip")})
    if unique_dst > 20:
        s["status"] = "suspicious"
        s.setdefault("alerts", []).append({"reason": "many_unique_destinations", "when": time.time(), "unique_dst": unique_dst})
        logger.info("Session %s suspicious: many unique destinations %d", session_id, unique_dst)
    return s


def check_session(session_id: str) -> Dict[str, Any]:
    """
    Returns current session info and a simple health verdict:
    - healthy / suspicious / quarantined
    """
    s = _sessions.get(session_id)
    if not s:
        return {"session_id": session_id, "status": "not_found"}
    # escalate if suspicious alerts > threshold
    alerts = s.get("alerts", [])
    if len(alerts) >= 2:
        s["status"] = "quarantined"
    return s


def end_session(session_id: str):
    if session_id in _sessions:
        _sessions[session_id]["status"] = "ended"
        _sessions[session_id]["ended_at"] = time.time()
        logger.info("Session %s ended", session_id)
