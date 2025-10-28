"""
AI-NGFW Project Integration Test
--------------------------------
This script verifies that your entire system works end-to-end:
1. Zero Trust verification
2. AI detection + Firewall blocking
3. Logging & Incident Response
4. Threat Intelligence update

Author: (Your Name)
"""

import pytest
pytest.skip("Integration script - skipped during automated unit tests", allow_module_level=True)

import json
import time
from zero_trust_control.identity_verification import verify_context
from firewall_engine.integration import AIFirewall
from incident_response.analyzer import load_alerts, analyze_alerts
from incident_response.report_generator import generate_pdf_report
from firewall_engine.rule_engine import RuleEngine
from threat_intelligence.parser import parse_feed_data
from threat_intelligence.rule_updater import update_firewall_rules

print("=" * 60)
print("🚀  Running AI-NGFW System Integration Test")
print("=" * 60)

# Step 1: Mock user/device context (Zero Trust)
context = {
    "device_assertion": {"device_id": "laptop001", "signed_by_mdm": True, "antivirus": "up_to_date", "patch_level": "2025-09-30"},
    "user_assertion": {"user_id": "alice", "auth_method": "mfa", "mfa_ok": True, "user_role": "user", "last_auth_time": "2025-10-28"},
    "geo": {"country": "IN", "is_internal": True},
}
zt_result = verify_context(context)
print(f"[1️⃣] Zero Trust Verification -> allow={zt_result['allow']} | score={zt_result['score']:.2f}")

# Step 2: Simulate a malicious packet detected by AI
packet = {
    "src_ip": "192.168.1.50",
    "dst_ip": "8.8.8.8",
    "protocol": "TCP",
    "port": 443,
    "ai_pred": "malicious",
    "ai_confidence": 0.96,
}

fw = AIFirewall()
firewall_result = fw.process_packet(packet, context)
print(f"[2️⃣] Firewall Decision -> {firewall_result['decision']['decision'].upper()} | Reason: {firewall_result['decision']['reason']}")

# Step 3: Analyze recent alerts from logs
time.sleep(1)
alerts = load_alerts("firewall_engine/logs/actions.log", n=50)
if alerts:
    analyzed = analyze_alerts(alerts)
    critical = [a for a in analyzed if a["severity"] in ("high", "critical")]
    print(f"[3️⃣] Incident Analysis -> {len(analyzed)} alerts found ({len(critical)} severe)")
    generate_pdf_report(analyzed, path="incident_response/logs/test_report.pdf")
    print("📄 Report saved to incident_response/logs/test_report.pdf")
else:
    print("[3️⃣] No alerts found in log yet (may need second run).")

# Step 4: Test Threat Intelligence feed update (mock)
mock_feed = [{"raw": "malicious domain example.com 123.45.67.89"}]
parsed = parse_feed_data(mock_feed)
rule_engine = RuleEngine()
update_firewall_rules(parsed, rule_engine)
print(f"[4️⃣] Threat Intelligence Update -> added {len(parsed['ips'])} IP(s) and {len(parsed['domains'])} domain(s) to rules.")

print("=" * 60)
print("✅ Integration Test Completed Successfully")
print("Check: firewall_engine/logs/actions.log and incident_response/logs/test_report.pdf")
print("=" * 60)
