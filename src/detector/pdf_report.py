import io
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

from analysis.explanations import explain_indicator, defang

_HEADER_STYLE = [
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ("FONTSIZE", (0, 0), (-1, -1), 8),
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
]


def _e(value):
    """Escape attacker-controlled text: reportlab Paragraphs parse XML-like markup,
    so an email subject such as '<b>' or '&' must never reach one unescaped."""
    return escape(str(value if value is not None else ""))


def _cell(text, styles):
    return Paragraph(_e(text), styles["BodyText"])


def _table(rows, widths, styles, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle(_HEADER_STYLE if header else [("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    return t


def build_pdf_report(data: dict) -> io.BytesIO:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    small = styles["BodyText"].clone("small", fontSize=8, leading=10)

    def para(text):
        return Paragraph(_e(text), small)

    story = [
        Paragraph("Explainable Phishing Email Detector — Analysis Report", styles["Title"]),
        Spacer(1, 8),
        Paragraph(f"Submission #{_e(data['id'])} — {_e(data['filename'])}", styles["Heading2"]),
        Spacer(1, 6),
        Paragraph(f"<b>Verdict:</b> {_e(data['verdict']).upper()} &nbsp;&nbsp; <b>Risk score:</b> {_e(data['risk_score'])}/100", styles["Normal"]),
        Paragraph(f"<b>Sender:</b> {_e(data['sender'])}", styles["Normal"]),
        Paragraph(f"<b>Subject:</b> {_e(data['subject'])}", styles["Normal"]),
        Paragraph(f"<b>SHA-256:</b> {_e(data['sha256'])}", styles["Normal"]),
        Paragraph(f"<b>SPF/DKIM/DMARC:</b> {_e(data['spf'])} / {_e(data['dkim'])} / {_e(data['dmarc'])}", styles["Normal"]),
        Paragraph(
            f"<b>Score breakdown:</b> rules {_e(data.get('rule_score'))}/100 · text model {_e(data.get('text_probability'))} · "
            f"structured model {_e(data.get('structured_probability'))} · blended ML {_e(data['ml_probability'])}",
            styles["Normal"]),
        Paragraph(f"<b>Quarantined:</b> {'yes' if data.get('quarantined') else 'no'} &nbsp;&nbsp; "
                  f"<b>Analyst feedback:</b> {_e(data.get('analyst_feedback') or 'none')}", styles["Normal"]),
        Spacer(1, 10),
        Paragraph("Rule-based indicators", styles["Heading3"]),
    ]

    if data["rule_indicators"]:
        rows = [["Indicator", "Meaning"]] + [[para(i), para(explain_indicator(i) or "-")] for i in data["rule_indicators"]]
        story.append(_table(rows, [55 * mm, 105 * mm], styles))
    else:
        story.append(Paragraph("None triggered.", styles["Normal"]))

    story += [Spacer(1, 10), Paragraph("Links, domains and threat intelligence (defanged)", styles["Heading3"])]
    if data.get("indicators"):
        rows = [["Type", "Indicator", "Findings", "Intel"]]
        for i in data["indicators"]:
            findings = ", ".join(i["findings"]) + (" [blocklisted]" if i["blocklisted"] else "")
            rows.append([para(i["kind"]), para(defang(i["value"])[:120]), para(findings or "-"), para(i["intel_verdict"] or "not checked")])
        story.append(_table(rows, [25 * mm, 70 * mm, 45 * mm, 20 * mm], styles))
    else:
        story.append(Paragraph("No links or attachments found.", styles["Normal"]))

    story += [Spacer(1, 10), Paragraph("Explainability — top feature contributions", styles["Heading3"])]
    if data["ml_explanation"]:
        rows = [["Source", "Feature / term", "Value", "Contribution"]] + [
            [para(e.get("source", "structured")), para(e["feature"]), para(e["value"]), para(e["contribution"])]
            for e in data["ml_explanation"]
        ]
        story.append(_table(rows, [25 * mm, 70 * mm, 30 * mm, 35 * mm], styles))

    story += [Spacer(1, 10), Paragraph("Attachments (metadata/hash only — never opened or stored)", styles["Heading3"])]
    if data["attachments"]:
        rows = [["Filename", "Type", "Size", "SHA-256"]] + [
            [para(a["filename"]), para(a["declared_type"]), para(a["size_bytes"]), para(a["sha256"][:16] + "…")]
            for a in data["attachments"]
        ]
        story.append(_table(rows, [50 * mm, 40 * mm, 25 * mm, 45 * mm], styles))
    else:
        story.append(Paragraph("No attachments.", styles["Normal"]))

    doc.build(story)
    buf.seek(0)
    return buf
