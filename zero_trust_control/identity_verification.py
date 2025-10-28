# zero_trust_control/identity_verification.py
"""
Identity verification utilities.

Functions:
- verify_device(device_assertion) -> bool, details
- verify_user(user_assertion) -> bool, details
- verify_context(context) -> dict (combines checks: MFA, device posture, geo, time-of-day)
- Example integration point: call before granting access; returns trust attributes.
"""

import time
import hashlib
import logging
from typing import Dict, Any

logger = logging.getLogger("zero_trust.identity")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf8")).hexdigest()


def verify_device(device_assertion: Dict[str, Any]) -> Dict[str, Any]:
    """
    device_assertion expected keys (example):
    {
      "device_id": "abc123",
      "os": "Android",
      "patch_level": "2025-06-01",
      "antivirus": "up_to_date"/"outdated",
      "signed_by_mdm": True/False,
      "device_presented_token": "<token>"
    }

    Returns dict:
    { "ok": True/False, "score": 0.0-1.0, "reasons": [...] }
    """
    reasons = []
    score = 0.5  # start neutral

    if device_assertion.get("signed_by_mdm"):
        reasons.append("MDM signed")
        score += 0.3
    else:
        reasons.append("No MDM signature")
        score -= 0.2

    if device_assertion.get("antivirus") == "up_to_date":
        reasons.append("AV up-to-date")
        score += 0.1
    else:
        reasons.append("AV outdated or missing")
        score -= 0.1

    # Patch recency heuristic (simple)
    patch = device_assertion.get("patch_level")
    if patch:
        try:
            # expected YYYY-MM-DD
            patch_ts = time.mktime(time.strptime(patch, "%Y-%m-%d"))
            age_days = (time.time() - patch_ts) / 86400.0
            if age_days < 30:
                reasons.append("Patch recent")
                score += 0.1
            elif age_days < 90:
                reasons.append("Patch moderately recent")
                score += 0.0
            else:
                reasons.append("Patch old")
                score -= 0.15
        except Exception:
            reasons.append("Patch date parse failed")
            score -= 0.05

    # token check (stateless demonstration)
    token = device_assertion.get("device_presented_token")
    if token:
        # in real setup this would validate against a secure store / MDM
        if _hash_token(token)[:6] == "000000":  # dummy condition for example
            reasons.append("Device token valid")
            score += 0.2
        else:
            reasons.append("Device token present but not validated")
            score += 0.0
    else:
        reasons.append("No device token presented")
        score -= 0.1

    score = max(0.0, min(1.0, score))
    ok = score >= 0.6
    logger.info("Device verification: ok=%s score=%.2f reasons=%s", ok, score, reasons)
    return {"ok": ok, "score": score, "reasons": reasons}


def verify_user(user_assertion: Dict[str, Any]) -> Dict[str, Any]:
    """
    user_assertion example:
    {
      "user_id": "alice",
      "auth_method": "password" / "mfa" / "sso",
      "mfa_ok": True/False,
      "last_auth_time": "2025-10-28T12:34:00Z",
      "user_role": "admin"/"user"/...
    }
    Returns dict with score & reasons.
    """
    reasons = []
    score = 0.5

    method = user_assertion.get("auth_method", "password")
    if method == "mfa" or user_assertion.get("mfa_ok"):
        reasons.append("MFA verified")
        score += 0.3
    elif method == "sso":
        reasons.append("SSO auth")
        score += 0.15
    else:
        reasons.append("Password-only or unknown auth")
        score -= 0.2

    role = user_assertion.get("user_role", "user")
    if role == "admin":
        reasons.append("Admin role -> requires stricter checks")
        score -= 0.1

    # recency of auth: prefer recent
    # (expect ISO8601-like string, but we keep it tolerant)
    last = user_assertion.get("last_auth_time")
    if last:
        try:
            # attempt simple parse of YYYY-MM-DD...
            t = time.strptime(last[:10], "%Y-%m-%d")
            age_days = (time.time() - time.mktime(t)) / 86400.0
            if age_days < 1:
                reasons.append("Recent authentication")
                score += 0.1
            elif age_days > 30:
                reasons.append("Stale authentication")
                score -= 0.1
        except Exception:
            reasons.append("Could not parse last_auth_time")
            score -= 0.05

    score = max(0.0, min(1.0, score))
    ok = score >= 0.6
    logger.info("User verification: ok=%s score=%.2f reasons=%s", ok, score, reasons)
    return {"ok": ok, "score": score, "reasons": reasons}


def verify_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Combine device + user + contextual signals.
    Expected keys: 'device_assertion', 'user_assertion', 'geo', 'time_of_day', etc.
    Returns combined verdict and attributes for policy engine.
    """
    dres = verify_device(context.get("device_assertion", {}))
    ures = verify_user(context.get("user_assertion", {}))
    # simple aggregator: weighted average
    combined_score = (0.6 * dres["score"]) + (0.4 * ures["score"])
    reasons = ["device:"+(";".join(dres["reasons"])), "user:"+(";".join(ures["reasons"]))]

    # Add geo-check heuristic (block suspicious countries example)
    geo = context.get("geo")
    if geo:
        blocked_countries = context.get("blocked_countries", [])
        if geo.get("country") in blocked_countries:
            combined_score -= 0.4
            reasons.append(f"geo:{geo.get('country')} blocked")

    combined_score = max(0.0, min(1.0, combined_score))
    allow = combined_score >= 0.65
    logger.info("Context verification: allow=%s score=%.2f reasons=%s", allow, combined_score, reasons)
    return {"allow": allow, "score": combined_score, "reasons": reasons}
