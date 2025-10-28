# firewall_engine/__init__.py
"""
Firewall Engine for AI-NGFW.

Provides:
- rule_engine       → dynamic firewall rule management
- packet_filter     → applies rules to packets/flows
- response_automation → auto block / isolate / alert actions
- integration       → bridge between AI detection & enforcement
"""
__all__ = ["rule_engine", "packet_filter", "response_automation", "integration"]
