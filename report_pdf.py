"""
Builds the downloadable PDF incident report with ReportLab.

Input: one incident (common format, as a dict) and the AI sections for it.
The report contains a snapshot table, the AI findings, indicator, ATT&CK and
timeline tables, an indicator chart, recommendations and a disclaimer.
"""
import re
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BLUE = colors.HexColor("#0f4c81")
ROW_TINT = colors.HexColor("#eef3f8")
GRID = colors.HexColor("#c9d6e2")
TABLE_WIDTH = 451   # width of the printable area on A4 with default margins

_REPLACEMENTS = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "✓": "", "✔": "", "✗": "", "\u2011": "-",
                 "\u00a0": " ", "\u202f": " "}


def pdf_safe(text) -> str:
    """The built-in PDF fonts only cover Latin-1 style characters, so drop what they cannot show."""
    text = str(text or "")
    for old, new in _REPLACEMENTS.items():
        text = text.replace(old, new)
    return text.encode("cp1252", "ignore").decode("cp1252")


def inline_markup(text) -> str:
    """Escape text for ReportLab paragraphs and turn **bold** into <b>bold</b>."""
    safe = escape(pdf_safe(text)).replace("`", "")
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("T", parent=base["Title"], textColor=colors.HexColor("#1a1a2e")),
        "heading": ParagraphStyle("H", parent=base["Heading2"], textColor=BLUE, spaceBefore=12, spaceAfter=6,
                                keepWithNext=1),
        "label": ParagraphStyle("L", parent=base["BodyText"], leading=15, keepWithNext=1),
        "body": ParagraphStyle("B", parent=base["BodyText"], leading=15),
        "bullet": ParagraphStyle("BL", parent=base["BodyText"], leading=15, leftIndent=16, bulletIndent=4),
        "cell": ParagraphStyle("C", parent=base["BodyText"], fontSize=8, leading=10, wordWrap="CJK"),
        "footer": ParagraphStyle("F", parent=base["Normal"], fontSize=8, textColor=colors.grey),
    }


def text_flowables(text, styles):
    """Turn multi-line AI text into paragraphs, keeping bullets and numbered steps readable."""
    flowables = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        heading = re.match(r"^#{1,6}\s*(.+)$", line)
        bullet = re.match(r"^[-*\u2022]\s+(.*)$", line)
        if heading:
            flowables.append(Paragraph(f"<b>{inline_markup(heading.group(1))}</b>", styles["body"]))
        elif bullet:
            flowables.append(Paragraph(inline_markup(bullet.group(1)), styles["bullet"], bulletText="\u2022"))
        elif re.match(r"^\d+[.)]\s", line):
            flowables.append(Paragraph(inline_markup(line), styles["bullet"]))
        else:
            flowables.append(Paragraph(inline_markup(line), styles["body"]))
        flowables.append(Spacer(1, 2))
    return flowables or [Paragraph("Not available.", styles["body"])]


def _table(rows, widths, styles, header=True):
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, ROW_TINT]),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands += [("BACKGROUND", (0, 0), (-1, 0), BLUE), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                     ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
    else:
        commands.append(("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"))
    table.setStyle(TableStyle(commands))
    return table


def _cell(text, styles):
    return Paragraph(inline_markup(text), styles["cell"])


def _snapshot_rows(incident, styles):
    host = incident.get("host") or {}
    net = incident.get("network") or {}
    pairs = [
        ("Incident ID", incident.get("id")), ("Title", incident.get("title")),
        ("Source system", incident.get("source")), ("Severity (source)", incident.get("severity")),
        ("Status", incident.get("status")), ("Created", incident.get("created_at")),
        ("Threat actor", incident.get("threat_actor")),
        ("Hostname", host.get("hostname")), ("Operating system", host.get("os")),
        ("Department", host.get("department")), ("User", host.get("username")),
        ("Internal IP", host.get("ip")), ("Source IP", net.get("source_ip")),
        ("Destination IPs", ", ".join(net.get("destination_ips") or [])),
        ("Protocol", net.get("protocol")), ("Port", net.get("port")),
        ("Country", net.get("country")), ("Data sent out", net.get("bytes_out")),
    ]
    return [[label, _cell(value, styles)] for label, value in pairs if value]


def _indicator_rows(incident, styles):
    ind = incident.get("indicators") or {}
    kinds = [("IP address", "ips", 10), ("Domain", "domains", 10), ("File hash", "hashes", 5),
             ("Email", "emails", 5), ("CVE", "cves", 10), ("URL", "urls", 5)]
    rows = []
    for label, key, limit in kinds:
        for value in (ind.get(key) or [])[:limit]:
            rows.append([label, _cell(value, styles)])
    return rows


def _indicator_chart(incident):
    ind = incident.get("indicators") or {}
    labels = ["IPs", "Domains", "Hashes", "Emails", "CVEs", "Techniques"]
    values = [len(ind.get("ips") or []), len(ind.get("domains") or []), len(ind.get("hashes") or []),
              len(ind.get("emails") or []), len(ind.get("cves") or []), len(incident.get("techniques") or [])]
    drawing = Drawing(430, 170)
    chart = VerticalBarChart()
    chart.x, chart.y, chart.width, chart.height = 40, 25, 370, 120
    chart.data = [values]
    chart.categoryAxis.categoryNames = labels
    chart.categoryAxis.labels.fontSize = 8
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueStep = max(1, max(values) // 5 or 1)
    chart.bars[0].fillColor = BLUE
    chart.barWidth = 12
    drawing.add(chart)
    return drawing


def build_pdf_report(incident: dict, sections: dict, model_name: str = "", playbook_sources=None) -> bytes:
    """Return the finished PDF as bytes."""
    styles = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=0.8 * inch, bottomMargin=0.8 * inch,
                            title=f"Incident report {incident.get('id', '')}", author="CyberGuardian AI")
    story = []

    story.append(Paragraph("CyberGuardian AI - Incident Response Report", styles["title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%d %B %Y, %H:%M')}", styles["body"]))
    story.append(Paragraph(f"Incident: {inline_markup(incident.get('id', ''))} - "
                           f"{inline_markup(incident.get('title', ''))}", styles["body"]))
    story.append(Spacer(1, 10))

    snapshot = _snapshot_rows(incident, styles)
    if snapshot:
        story += [Paragraph("Incident Snapshot", styles["heading"]),
                  _table(snapshot, [130, TABLE_WIDTH - 130], styles, header=False), Spacer(1, 8)]

    summary = sections.get("Incident Summary") or incident.get("summary") or "Not available."
    story += [Paragraph("Summary", styles["heading"])] + text_flowables(summary, styles)

    story.append(Paragraph("Findings", styles["heading"]))
    for label in ("Attack Type", "Severity", "Root Cause", "Explanation"):
        story.append(Paragraph(f"<b>{label}</b>", styles["label"]))
        story += text_flowables(sections.get(label, "Not available."), styles)
        story.append(Spacer(1, 4))

    indicator_rows = _indicator_rows(incident, styles)
    if indicator_rows:
        story += [Paragraph("Indicators of Compromise", styles["heading"]),
                  _table([["Type", "Value"]] + indicator_rows, [110, TABLE_WIDTH - 110], styles),
                  Spacer(1, 8), Paragraph("Indicator counts", styles["heading"]),
                  _indicator_chart(incident)]

    techniques = incident.get("techniques") or []
    if techniques:
        rows = [["ID", "Technique"]] + [[t["id"], _cell(t.get("name", ""), styles)] for t in techniques]
        story += [Paragraph("MITRE ATT&amp;CK Techniques", styles["heading"]),
                  _table(rows, [90, TABLE_WIDTH - 90], styles), Spacer(1, 8)]

    timeline = incident.get("timeline") or []
    if timeline:
        rows = [["Time", "Event"]] + [[e["time"], _cell(e["event"], styles)] for e in timeline[:25]]
        story += [Paragraph("Attack Timeline", styles["heading"]),
                  _table(rows, [70, TABLE_WIDTH - 70], styles), Spacer(1, 8)]

    story.append(Paragraph("Recommendations", styles["heading"]))
    for label in ("Mitigation", "Best Practices"):
        story.append(Paragraph(f"<b>{label}</b>", styles["label"]))
        story += text_flowables(sections.get(label, "Not available."), styles)
        story.append(Spacer(1, 4))

    if playbook_sources:
        rows = [["Ref", "Playbook document"]] + [
            [src["ref"], _cell(src["doc"] + (f", page {src['page']}" if src.get("page") else ""), styles)]
            for src in playbook_sources]
        story += [Paragraph("Playbook References", styles["heading"]),
                  _table(rows, [50, TABLE_WIDTH - 50], styles), Spacer(1, 8)]

    story += [Spacer(1, 12), Paragraph("Disclaimer", styles["heading"])]
    story += text_flowables(
        sections.get("Disclaimer") or "This is an AI-generated analysis and must be reviewed by a "
                                      "qualified security professional before action is taken.", styles)
    footer = "Generated by CyberGuardian AI"
    if model_name:
        footer += f" using {inline_markup(model_name)}"
    story += [Spacer(1, 20), Paragraph(footer, styles["footer"])]

    doc.build(story)
    return buffer.getvalue()
