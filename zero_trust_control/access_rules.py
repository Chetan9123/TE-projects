# zero_trust_control/access_rules.py
"""
Dynamic policy / rule engine for Zero Trust least-privilege enforcement.

Provides:
- Rule class and RuleEngine
- Example policies (time-based, role-based, score-threshold)
- evaluate_request(context, resource) -> decision dict
"""

import logging
from typing import Dict, Any, Callable, List
import datetime

logger = logging.getLogger("zero_trust.rules")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


class Rule:
    """
    Rule holds a predicate function that given (context, resource) -> True/False
    and an action: 'allow', 'deny', 'challenge' (e.g., request MFA), 'quarantine'.
    """
    def __init__(self, name: str, predicate: Callable[[Dict[str, Any], Dict[str, Any]], bool], action: str, priority: int = 100):
        self.name = name
        self.predicate = predicate
        self.action = action
        self.priority = priority

    def applies(self, context: Dict[str, Any], resource: Dict[str, Any]) -> bool:
        try:
            return bool(self.predicate(context, resource))
        except Exception as e:
            logger.exception("Rule %s predicate failed: %s", self.name, e)
            return False


class RuleEngine:
    def __init__(self):
        self.rules: List[Rule] = []

    def add_rule(self, rule: Rule):
        self.rules.append(rule)
        # keep sorted by priority (lower number = higher priority)
        self.rules.sort(key=lambda r: r.priority)

    def evaluate(self, context: Dict[str, Any], resource: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate rules in order; return first matching action.
        If none match, default to 'deny' (Zero Trust).
        """
        for r in self.rules:
            if r.applies(context, resource):
                logger.info("Rule matched: %s -> action=%s", r.name, r.action)
                return {"action": r.action, "rule": r.name}
        logger.info("No rules matched -> deny by default")
        return {"action": "deny", "rule": "default-deny"}


# ---------------------------
# Example rule predicates
# ---------------------------
def always_allow_admin_network(context, resource):
    # allow if user is admin and accessing from internal network
    u = context.get("user_assertion", {})
    geo = context.get("geo", {})
    if u.get("user_role") == "admin" and geo.get("is_internal", False):
        return True
    return False


def trust_score_above(threshold: float):
    def predicate(context, resource):
        # context expected to have 'trust_score' float
        score = context.get("trust_score") or context.get("score") or 0.0
        return float(score) >= threshold
    return predicate


def time_of_day_allowed(start_h: int, end_h: int):
    def predicate(context, resource):
        tz = context.get("time_zone_offset", 0)
        now_utc = datetime.datetime.utcnow()
        # naive local hour
        hour = (now_utc.hour + tz) % 24
        return start_h <= hour < end_h
    return predicate


# ---------------------------
# Example: build a default rule engine
# ---------------------------
def default_rule_engine() -> RuleEngine:
    re = RuleEngine()
    # 1) High priority: block if trust score too low
    re.add_rule(Rule("block_low_trust", predicate=trust_score_above(0.85).__neg__ if False else (lambda c,r: (c.get("trust_score") or c.get("score") or 0.0) < 0.3), action="deny", priority=10))  # low trust -> deny
    # 2) Allow high-trust sessions
    re.add_rule(Rule("allow_high_trust", predicate=trust_score_above(0.8), action="allow", priority=20))
    # 3) Time-based rule: only allow during working hours (example)
    re.add_rule(Rule("working_hours_allow", predicate=time_of_day_allowed(7, 20), action="allow", priority=50))
    # 4) Admin internal network rule (higher priority than generic working hours)
    re.add_rule(Rule("admin_internal", predicate=always_allow_admin_network, action="allow", priority=15))
    return re


# ---------------------------
# Example evaluation helper
# ---------------------------
def evaluate_request(context: Dict[str, Any], resource: Dict[str, Any], engine: RuleEngine = None) -> Dict[str, Any]:
    """
    Given a context (from identity_verification.verify_context + any additional signals),
    and a resource dict (resource_id, required_privilege_level, sensitivity), returns decision dict.
    """
    if engine is None:
        engine = default_rule_engine()
    # normalize context keys
    if "trust_score" not in context and "score" in context:
        context["trust_score"] = context["score"]
    decision = engine.evaluate(context, resource)
    # attach reason & metadata
    decision["context_score"] = context.get("trust_score", 0.0)
    decision["resource"] = resource
    return decision
