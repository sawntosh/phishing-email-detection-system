import io
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


def build_pdf_report(data: dict) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("Explainable Phishing Email Detector — Analysis Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(f"Submission #{data['id']} — {data['filename']}", styles["Heading2"]),
        Spacer(1, 6),
        Paragraph(f"<b>Verdict:</b> {data['verdict'].upper()} &nbsp;&nbsp; <b>Risk score:</b> {data['risk_score']}/100", styles["Normal"]),
        Paragraph(f"<b>Sender:</b> {data['sender']}", styles["Normal"]),
        Paragraph(f"<b>Subject:</b> {data['subject']}", styles["Normal"]),
        Paragraph(f"<b>SHA-256:</b> {data['sha256']}", styles["Normal"]),
        Paragraph(f"<b>SPF/DKIM/DMARC:</b> {data['spf']} / {data['dkim']} / {data['dmarc']}", styles["Normal"]),
        Paragraph(f"<b>ML phishing probability:</b> {data['ml_probability']}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("Rule-based indicators", styles["Heading3"]),
    ]
    if data["rule_indicators"]:
        rows = [[i] for i in data["rule_indicators"]]
        t = Table([["Indicator"]] + rows, colWidths=[160 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("None triggered.", styles["Normal"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph("Top ML feature contributions (explainability)", styles["Heading3"]))
    if data["ml_explanation"]:
        rows = [[e["feature"], str(e["value"]), str(e["contribution"])] for e in data["ml_explanation"]]
        t2 = Table([["Feature", "Value", "Contribution"]] + rows, colWidths=[70 * mm, 40 * mm, 50 * mm])
        t2.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(t2)

    story.append(Spacer(1, 10))
    story.append(Paragraph("Attachments (metadata/hash only — never opened or stored)", styles["Heading3"]))
    if data["attachments"]:
        rows = [[a["filename"], a["declared_type"], str(a["size_bytes"]), a["sha256"][:16] + "…"] for a in data["attachments"]]
        t3 = Table([["Filename", "Type", "Size", "SHA-256"]] + rows, colWidths=[50 * mm, 40 * mm, 25 * mm, 45 * mm])
        t3.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story.append(t3)
    else:
        story.append(Paragraph("No attachments.", styles["Normal"]))

    doc.build(story)
    buf.seek(0)
    return buf
