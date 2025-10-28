# incident_response/notifier.py
"""
Notification handler for incident alerts via email or Slack (optional).
"""

import smtplib
import logging
from email.mime.text import MIMEText
from typing import Dict, Any

logger = logging.getLogger("incident.notifier")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def send_email_notification(to_email: str, subject: str, body: str, smtp_server="smtp.gmail.com", smtp_port=587,
                            from_email="ai.ngfw@example.com", password="examplepassword"):
    try:
        msg = MIMEText(body)
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, password)
            server.send_message(msg)
        logger.info("Email sent to %s", to_email)
    except Exception as e:
        logger.error("Failed to send email: %s", e)


def notify_admin(incident: Dict[str, Any], email: str):
    """Notify administrator with incident summary."""
    subject = f"Incident Alert - {incident.get('severity', 'Unknown').upper()}"
    body = f"Action: {incident.get('action')}\nSeverity: {incident.get('severity')}\nDetails: {incident}"
    send_email_notification(email, subject, body)
