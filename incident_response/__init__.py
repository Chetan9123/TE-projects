# incident_response/__init__.py
"""
Incident Response module for AI-NGFW.

Provides:
- analyzer: analyzes alert data and classifies severity
- responder: automated mitigation or escalation
- report_generator: creates detailed reports
- notifier: sends notifications to admins
"""
__all__ = ["analyzer", "responder", "report_generator", "notifier"]
