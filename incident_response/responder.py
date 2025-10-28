# incident_response/responder.py
"""
Automated incident response engine.
- containment (block IP, isolate host)
- escalation (notify admin)
- tagging (update rule engine or logs)
"""

import logging
from typing import Dict, Any
from firewall_engine.response_automation import block_ip, isolate_host, send_alert
from firewall_engine.rule_engine import RuleEngine

logger = logging.getLogger("incident.responder")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def respond_to_incident(incident: Dict[str, Any], rule_engine: RuleEngine):
    sev = incident.get("severity", "low")
    data = incident.get("data", {})
    src_ip = data.get("ip") or data.get("src_ip")

    if sev == "critical":
        logger.warning("Critical incident: blocking %s", src_ip)
        if src_ip:
            block_ip(src_ip, rule_engine)
        send_alert("Critical incident blocked", incident)
    elif sev == "high":
        if src_ip:
            isolate_host(src_ip)
        send_alert("High severity incident isolated", incident)
    elif sev == "medium":
        send_alert("Medium severity alert review", incident)
    else:
        logger.info("Low severity alert, logged only.")
