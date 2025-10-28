# firewall_engine/response_automation.py
"""
Automated responses triggered by packet_filter decisions.

Actions:
- block_ip()
- isolate_host()
- send_alert()
- update_rules()
"""

import logging
import os
import json
import datetime
from typing import Dict, Any
from firewall_engine.rule_engine import RuleEngine

logger = logging.getLogger("firewall.response")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)

LOG_FILE = "firewall_engine/logs/actions.log"


def log_action(action: str, data: Dict[str, Any]):
    os.makedirs(os.path.dirname(LOG_FILE) or ".", exist_ok=True)
    entry = {"timestamp": datetime.datetime.utcnow().isoformat(), "action": action, "data": data}
    with open(LOG_FILE, "a", encoding="utf8") as f:
        f.write(json.dumps(entry) + "\n")


def block_ip(ip: str, rule_engine: RuleEngine):
    rule = {"id": f"auto_block_{ip}", "src_ip": ip, "dst_ip": "*", "protocol": "*", "port": "*", "action": "deny"}
    rule_engine.add_rule(rule)
    log_action("block_ip", {"ip": ip})
    logger.warning("Blocked IP: %s", ip)


def isolate_host(host_ip: str):
    log_action("isolate_host", {"host": host_ip})
    logger.warning("Host isolated (simulation): %s", host_ip)


def send_alert(message: str, details: Dict[str, Any]):
    log_action("alert", {"message": message, "details": details})
    logger.info("ALERT: %s | %s", message, details)


def respond_to_decision(decision: Dict[str, Any], rule_engine: RuleEngine):
    """
    decision = {'decision':'block','packet':{...},'reason':...}
    """
    pkt = decision.get("packet", {})
    if decision.get("decision") == "block":
        block_ip(pkt.get("src_ip"), rule_engine)
        send_alert("Blocked malicious packet", pkt)
    elif decision.get("decision") == "allow":
        log_action("allow", pkt)
    else:
        isolate_host(pkt.get("src_ip"))
