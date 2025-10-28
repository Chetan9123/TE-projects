"""
main.py — Entry point for AI-NGFW
---------------------------------
Orchestrates all core modules:
  - Zero Trust verification
  - AI detection
  - Firewall engine
  - Threat intelligence update
  - Incident response
"""

import time
import yaml
import logging
from zero_trust_control.identity_verification import verify_context
from firewall_engine.integration import AIFirewall
from incident_response.analyzer import analyze_alerts, load_alerts
from threat_intelligence.feed_fetcher import fetch_all_feeds
from threat_intelligence.parser import parse_feed_data
from threat_intelligence.rule_updater import update_firewall_rules
from firewall_engine.rule_engine import RuleEngine

# ========== Logging setup ==========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [MAIN] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("main")

def main():
    # ========== Load Configuration ==========
    with open("config.yaml", "r") as f:
        CONFIG = yaml.safe_load(f)

    logger.info("✅ Loaded configuration for %s", CONFIG["project"]["name"])

    # ========== Initialize Core Systems ==========
    firewall = AIFirewall()
    rule_engine = RuleEngine(CONFIG["firewall"]["rule_file"])

    # ========== Example Test Packet ==========
    packet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "8.8.8.8",
        "protocol": "TCP",
        "port": 443,
        "ai_pred": "malicious",
        "ai_confidence": 0.93,
    }

    context = {
        "device_assertion": {"signed_by_mdm": True, "antivirus": "up_to_date", "patch_level": "2025-09-30"},
        "user_assertion": {"auth_method": "mfa", "mfa_ok": True, "user_role": "user", "last_auth_time": "2025-10-28"},
        "geo": {"country": "IN"},
    }

    # ========== Step 1: Zero Trust ==========
    zt = verify_context(context)
    logger.info("Zero Trust Verification -> allow=%s | score=%.2f", zt["allow"], zt["score"])

    # ========== Step 2: AI Detection + Firewall ==========
    decision = firewall.process_packet(packet, context)
    logger.info("Firewall Decision -> %s | Reason: %s", decision["decision"]["decision"], decision["decision"]["reason"])

    # ========== Step 3: Incident Response ==========
    try:
        alerts = load_alerts(CONFIG["firewall"]["log_file"], n=50)
        analyzed = analyze_alerts(alerts)
        logger.info("Incident Response -> %d alerts analyzed", len(analyzed))
    except Exception as e:
        logger.warning("Incident Response skipped: %s", e)

    # ========== Step 4: Threat Intelligence Update ==========
    try:
        feeds = fetch_all_feeds()
        parsed = parse_feed_data(feeds)
        update_firewall_rules(parsed, rule_engine)
        logger.info("Threat Intel Update -> %d IPs and %d domains", len(parsed["ips"]), len(parsed["domains"]))
    except Exception as e:
        logger.warning("Threat Intel update skipped: %s", e)

    logger.info("✅ AI-NGFW system finished execution.")


if __name__ == "__main__":
    main()
