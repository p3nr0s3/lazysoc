"""PDF export of LazySOC period threat digests (reportlab, built-in fonts only)."""

import io
from typing import Any, Dict, List
from xml.sax.saxutils import escape

URGENCY_LABEL = {"critical": "KRITIS", "high": "TINGGI", "medium": "SEDANG", "low": "RENDAH"}
URGENCY_COLOR = {"critical": "#b91c1c", "high": "#b45309", "medium": "#1d4ed8", "low": "#475569"}
EXPLOIT_LABEL = {
    "exploited_in_the_wild": "Dieksploitasi aktif",
    "public_poc": "PoC publik",
    "not_reported": "Eksploitasi belum dilaporkan",
    "not_applicable": "Bukan kerentanan",
}
# Built-in PDF fonts only cover cp1252; map common typography so nothing renders as a black box.
_CHAR_MAP = str.maketrans({"→": "->", "←": "<-", "≤": "<=", "≥": ">=", "✓": "v", "⚠": "!"})


def _t(text: Any) -> str:
    """Escapes text for reportlab Paragraph markup and drops characters the base fonts cannot draw."""
    clean = str(text or "").translate(_CHAR_MAP)
    clean = clean.encode("cp1252", errors="replace").decode("cp1252")
    return escape(clean)


def digest_pdf(digest: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#475569"))
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=17, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12.5, spaceBefore=10, spaceAfter=4)
    h3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=10.5, spaceBefore=2, spaceAfter=2)

    def bullets(items: List[str], style=body):
        return ListFlowable([ListItem(Paragraph(_t(i), style), leftIndent=10) for i in items], bulletType="bullet", start="-", leftIndent=12)

    owner = digest.get("owner") or "Semua owner"
    mode = "Critical Tools" if digest.get("mode") == "critical" else "General"
    story = [
        Paragraph("LazySOC Threat Digest", h1),
        Paragraph(_t(f"Periode {digest.get('period_start')} s/d {digest.get('period_end')}  |  {mode}  |  {owner}"), body),
        Paragraph(_t(
            f"Dibuat {digest.get('created_at', '')} UTC dengan {digest.get('provider', '')} ({digest.get('model', '')}). "
            f"{digest.get('article_count', 0)} artikel diringkas dari {digest.get('articles_in_period', digest.get('article_count', 0))} artikel di periode ini."
        ), small),
        Paragraph("RAHASIA - berisi pemetaan produk ke owner/customer. Jangan dibagikan ke luar tim.", small),
        Spacer(1, 4 * mm),
        Paragraph("Ringkasan", h2),
        Paragraph(_t(digest.get("overview")), body),
    ]
    if digest.get("key_themes"):
        story += [Paragraph("Tema utama", h2), bullets(digest["key_themes"])]
    if digest.get("priority_actions"):
        story += [Paragraph("Tindakan prioritas", h2), bullets(digest["priority_actions"])]

    story.append(Paragraph("Rincian berita", h2))
    for a in digest.get("articles", []):
        urgency = a.get("urgency", "low")
        badge = Table(
            [[Paragraph(f'<font color="white"><b>{URGENCY_LABEL.get(urgency, urgency.upper())}</b></font>', small)]],
            colWidths=[22 * mm],
        )
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(URGENCY_COLOR.get(urgency, "#475569"))),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        meta = f"{a.get('source', '')} | {a.get('published_at', '')} UTC | {EXPLOIT_LABEL.get(a.get('exploitation'), '')}"
        block = [
            Table([[badge, Paragraph(f"<b>{_t(a.get('headline'))}</b>", h3)]], colWidths=[25 * mm, None],
                  style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)])),
            Paragraph(_t(meta), small),
            Paragraph(_t(a.get("summary")), body),
        ]
        products = [
            f"{m['product']} ({', '.join(m.get('owners', []))})" if m.get("level") == "product" else f"Vendor {m['vendor']} ({', '.join(m.get('owners', []))})"
            for m in a.get("watchlist_matches", [])
        ]
        if products:
            block.append(Paragraph(f"<b>Watchlist:</b> {_t('; '.join(products))}", small))
        if a.get("cves"):
            block.append(Paragraph(f"<b>CVE:</b> {_t(', '.join(a['cves']))}", small))
        if a.get("recommended_actions"):
            block.append(bullets(a["recommended_actions"], small))
        if a.get("link"):
            block.append(Paragraph(f'<link href="{_t(a["link"])}" color="#1d4ed8">{_t(a.get("title") or a["link"])}</link>', small))
        block.append(Spacer(1, 3 * mm))
        story.append(KeepTogether(block))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(15 * mm, 10 * mm, "LazySOC Threat Digest - RAHASIA")
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f"Hal. {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=16 * mm,
                            title="LazySOC Threat Digest", author="LazySOC")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
