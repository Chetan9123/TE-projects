# incident_response/report_generator.py
"""
Generate incident summary reports (PDF or JSON).
"""

import json
import logging
from datetime import datetime
from typing import List, Dict
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

logger = logging.getLogger("incident.report")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(ch)


def generate_json_report(incidents: List[Dict], path="incident_report.json"):
    with open(path, "w", encoding="utf8") as f:
        json.dump(incidents, f, indent=2)
    logger.info("JSON report saved at %s", path)
    return path


def generate_pdf_report(incidents: List[Dict], path="incident_report.pdf"):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4)
    story = [Paragraph("AI-NGFW Incident Report", styles["Title"]), Spacer(1, 12)]

    data = [["Timestamp", "Action", "Severity", "Details"]]
    for inc in incidents:
        data.append([
            inc.get("timestamp", "N/A"),
            inc.get("action", "N/A"),
            inc.get("severity", "N/A"),
            json.dumps(inc.get("data", {}))[:60] + "..."
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#333333")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated: {datetime.utcnow().isoformat()}", styles["Normal"]))
    doc.build(story)
    logger.info("PDF report generated at %s", path)
    return path
