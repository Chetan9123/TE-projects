# firewall_engine/packet_filter.py
"""
Packet filtering logic.

Uses rule_engine.RuleEngine to decide whether to ALLOW or BLOCK.
Integrates AI predictions to enforce adaptive blocking.
"""

import logging
from typing import Dict, Any
from firewall_engine.rule_engine import RuleEngine

logger = logging.getLogger("firewall.packet_filter")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


class PacketFilter:
    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine

    def inspect_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inspect packet fields and decide action.
        Packet dict example:
        {
          "src_ip": "192.168.1.2",
          "dst_ip": "8.8.8.8",
          "protocol": "TCP",
          "port": 80,
          "ai_pred": "benign"/"malicious",
          "ai_confidence": 0.95
        }
        """
        # If AI says malicious with high confidence → immediate block
        if packet.get("ai_pred") == "malicious" and packet.get("ai_confidence", 0) > 0.8:
            decision = "block"
            reason = "AI detected malicious"
        else:
            # check rule engine
            decision = self.rule_engine.decide(packet)
            reason = f"Rule-based decision ({decision})"
        logger.info("Packet decision=%s src=%s dst=%s reason=%s",
                    decision, packet.get("src_ip"), packet.get("dst_ip"), reason)
        return {"decision": decision, "reason": reason, "packet": packet}
