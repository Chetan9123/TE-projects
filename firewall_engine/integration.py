# firewall_engine/integration.py
"""
Integration between AI detection, Zero Trust control, and firewall engine.

This script demonstrates how an AI model prediction and Zero Trust score
can be combined to make and enforce a final firewall decision.
"""

import logging
from typing import Dict, Any

from firewall_engine.rule_engine import RuleEngine
from firewall_engine.packet_filter import PacketFilter
from firewall_engine.response_automation import respond_to_decision
from zero_trust_control.identity_verification import verify_context

logger = logging.getLogger("firewall.integration")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


class AIFirewall:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.filter = PacketFilter(self.rule_engine)

    def process_packet(self, packet: Dict[str, Any], context: Dict[str, Any]):
        """
        Combine AI model output + Zero Trust verification + rules.
        """
        # Step 1: get zero trust verdict
        zt = verify_context(context)
        trust_score = zt["score"]
        packet["trust_score"] = trust_score

        # Step 2: inspect via packet filter (AI + rules)
        decision = self.filter.inspect_packet(packet)

        # Step 3: automatic response
        respond_to_decision(decision, self.rule_engine)
        return {"zt": zt, "decision": decision}


if __name__ == "__main__":
    fw = AIFirewall()

    # Mock inputs
    pkt = {"src_ip": "192.168.1.50", "dst_ip": "8.8.8.8", "protocol": "TCP", "port": 443,
           "ai_pred": "malicious", "ai_confidence": 0.93}
    ctx = {
        "device_assertion": {"device_id": "devX", "signed_by_mdm": True, "antivirus": "up_to_date", "patch_level": "2025-09-30"},
        "user_assertion": {"user_id": "bob", "auth_method": "mfa", "mfa_ok": True, "user_role": "user", "last_auth_time": "2025-10-27"},
        "geo": {"country": "IN"}
    }

    result = fw.process_packet(pkt, ctx)
    print(result)
