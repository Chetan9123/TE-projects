# zero_trust_control/__init__.py
"""
Zero Trust Control module for AI-NGFW.

Provides:
- identity_verification: validate users/devices
- access_rules: least-privilege / policy enforcement helpers
- session_monitor: continuous session checking and anomalies detection
- trust_score_model: optional ML model to compute trust scores
"""
__all__ = ["identity_verification", "access_rules", "session_monitor", "trust_score_model"]
