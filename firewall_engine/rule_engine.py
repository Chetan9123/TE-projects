# firewall_engine/rule_engine.py
"""
RuleEngine maintains packet filtering rules (IP, port, protocol, action).

Example rule:
{
  "id": "rule1",
  "src_ip": "10.0.0.5",
  "dst_ip": "*",
  "protocol": "TCP",
  "port": 80,
  "action": "allow"
}
"""

import json
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger("firewall.rule_engine")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


class RuleEngine:
    def __init__(self, persist_path: str = "firewall_engine/logs/rules.json"):
        self.persist_path = persist_path
        self.rules: List[Dict[str, Any]] = []
        os.makedirs(os.path.dirname(persist_path) or ".", exist_ok=True)
        self.load()

    def load(self):
        if os.path.exists(self.persist_path):
            with open(self.persist_path, "r", encoding="utf8") as f:
                self.rules = json.load(f)
            logger.info("Loaded %d rules", len(self.rules))
        else:
            logger.info("No existing rules file found.")

    def save(self):
        with open(self.persist_path, "w", encoding="utf8") as f:
            json.dump(self.rules, f, indent=2)

    def add_rule(self, rule: Dict[str, Any]):
        self.rules.append(rule)
        self.save()
        logger.info("Added rule: %s", rule)

    def remove_rule(self, rule_id: str):
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.get("id") != rule_id]
        self.save()
        logger.info("Removed rule %s (%d→%d rules)", rule_id, before, len(self.rules))

    def match(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return the first matching rule or None.
        """
        for rule in self.rules:
            if (
                (rule.get("src_ip") in [packet.get("src_ip"), "*"])
                and (rule.get("dst_ip") in [packet.get("dst_ip"), "*"])
                and (rule.get("protocol") in [packet.get("protocol"), "*"])
                and (rule.get("port") in [packet.get("port"), "*", None])
            ):
                return rule
        return None

    def decide(self, packet: Dict[str, Any]) -> str:
        rule = self.match(packet)
        return rule.get("action") if rule else "deny"
