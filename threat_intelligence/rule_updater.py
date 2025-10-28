# threat_intelligence/rule_updater.py
"""
Automatically update firewall rules based on threat intelligence feeds.
"""

import logging
from typing import Dict, List
from firewall_engine.rule_engine import RuleEngine

logger = logging.getLogger("threat.rule_updater")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def update_firewall_rules(parsed_data: Dict[str, List[str]], rule_engine: RuleEngine):
    """Add deny rules for all new threat IPs."""
    ips = parsed_data.get("ips", [])
    added = 0
    for ip in ips[:1000]:  # limit for demo
        rule = {"id": f"threat_feed_{ip}", "src_ip": ip, "dst_ip": "*", "protocol": "*", "port": "*", "action": "deny"}
        rule_engine.add_rule(rule)
        added += 1
    logger.info("Added %d new rules from threat feeds", added)
