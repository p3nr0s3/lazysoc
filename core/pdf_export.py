"""PDF export of LazySOC period threat digests (reportlab, built-in fonts only).

Layout: title band + report metadata, KPI tiles, executive summary, priority actions, issue overview,
per-owner impact, one card per issue (articles about the same story merged), and a methodology note.
"""

import io
from datetime import datetime
from typing import Any, Dict, List
from xml.sax.saxutils import escape

URGENCY_LABEL = {"critical": "KRITIS", "high": "TINGGI", "medium": "SEDANG", "low": "RENDAH"}
URGENCY_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#1d4ed8", "low": "#475569"}
EXPLOIT_LABEL = {
    "exploited_in_the_wild": "Dieksploitasi aktif",
    "public_poc": "PoC publik",
    "not_reported": "Eksploitasi belum dilaporkan",
    "not_applicable": "Bukan kerentanan",
}
MONTHS = ["Jan", "Feb", "Mar", "Apr", "Mei", "Jun", "Jul", "Agu", "Sep", "Okt", "Nov", "Des"]

NAVY = "#0f172a"
ACCENT = "#0e7490"
INK = "#1e293b"
MUTED = "#64748b"
LINE = "#cbd5e1"
PANEL = "#f1f5f9"

# Built-in PDF fonts only cover cp1252; map common typography so nothing renders as a black box.
_CHAR_MAP = str.maketrans({"→": "->", "←": "<-", "≤": "<=", "≥": ">=", "✓": "v", "⚠": "!"})


def _t(text: Any) -> str:
    """Escapes text for reportlab Paragraph markup and drops characters the base fonts cannot draw."""
    clean = str(text or "").translate(_CHAR_MAP)
    clean = clean.encode("cp1252", errors="replace").decode("cp1252")
    return escape(clean)


def _date(value: str, with_time: bool = False) -> str:
    """'2026-10-21 18:57:34' -> '21 Okt 2026' (optionally with HH:MM UTC)."""
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "").strip()[:19])
    except ValueError:
        return str(value)
    text = f"{dt.day} {MONTHS[dt.month - 1]} {dt.year}"
    return f"{text} {dt:%H:%M} UTC" if with_time else text


def _period(digest: Dict[str, Any]) -> str:
    start, end = digest.get("period_start", ""), digest.get("period_end", "")
    return _date(start) if start == end else f"{_date(start)} - {_date(end)}"


def digest_pdf(digest: Dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    if "issues" not in digest:
        from core.digest import enrich_digest  # older stored digests predate issue grouping
        digest = enrich_digest(digest)

    c = colors.HexColor
    page_w, page_h = A4
    margin = 16 * mm
    width = page_w - 2 * margin

    def style(name, **kw):
        base = {"fontName": "Helvetica", "fontSize": 9, "leading": 12.5, "textColor": c(INK)}
        base.update(kw)
        return ParagraphStyle(name, **base)

    body = style("body")
    body_j = style("body_j", alignment=4)
    small = style("small", fontSize=7.8, leading=10.5, textColor=c(MUTED))
    cell = style("cell", fontSize=8.2, leading=10.8)
    cell_b = style("cell_b", fontSize=8.2, leading=10.8, fontName="Helvetica-Bold")
    head_cell = style("head_cell", fontSize=7.6, leading=10, fontName="Helvetica-Bold", textColor=colors.white)
    h2 = style("h2", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=c(NAVY), spaceBefore=12, spaceAfter=5)
    card_title = style("card_title", fontName="Helvetica-Bold", fontSize=10.2, leading=13, textColor=c(NAVY))
    label = style("label", fontSize=7.2, leading=9, textColor=c(MUTED), fontName="Helvetica-Bold")
    kpi_num = style("kpi_num", fontName="Helvetica-Bold", fontSize=17, leading=20, alignment=TA_CENTER, textColor=c(NAVY))
    kpi_lbl = style("kpi_lbl", fontSize=7.2, leading=9, alignment=TA_CENTER, textColor=c(MUTED))

    def section(title: str):
        return [CondPageBreak(30 * mm), Paragraph(_t(title), h2),
                Table([[""]], colWidths=[width], rowHeights=[1.2], style=[("LINEABOVE", (0, 0), (-1, -1), 1.2, c(ACCENT))]),
                Spacer(1, 3)]

    def badge(urgency: str) -> Table:
        tbl = Table([[Paragraph(f'<font color="white"><b>{URGENCY_LABEL.get(urgency, urgency.upper())}</b></font>',
                                style("badge", fontSize=7, leading=8.5, alignment=TA_CENTER))]], colWidths=[17 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c(URGENCY_COLOR.get(urgency, MUTED))),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
        ]))
        return tbl

    def cve_markup(issue: Dict[str, Any]) -> str:
        kev = set(issue.get("kev_cves", []))
        return ", ".join(f'<font color="{URGENCY_COLOR["critical"]}"><b>{_t(cv)} (KEV)</b></font>' if cv in kev else _t(cv)
                         for cv in issue.get("cves", [])) or "-"

    def products_markup(issue: Dict[str, Any]) -> str:
        parts = [f"<b>{_t(p['product'])}</b> ({_t(', '.join(p.get('owners', [])))})" for p in issue.get("products", [])]
        if not parts and issue.get("vendor_only"):
            vendors = ", ".join(sorted({v.get("vendor", "") for v in issue["vendor_only"]}))
            parts.append(f'<font color="{MUTED}">Vendor {_t(vendors)} disebut; produk spesifik tidak ada di watchlist</font>')
        return "<br/>".join(parts) or "-"

    owner = digest.get("owner") or "Semua owner"
    mode = "Critical Tools" if digest.get("mode") == "critical" else "General"
    kpis = digest.get("kpis", {})
    issues: List[Dict[str, Any]] = digest.get("issues", [])
    story: List[Any] = []

    # ---- Title band ------------------------------------------------------------
    band = Table([
        [Paragraph('<font color="#67e8f9"><b>LAZYSOC  |  THREAT INTELLIGENCE DIGEST</b></font>', style("eyebrow", fontSize=8, leading=10)),
         Paragraph('<font color="white"><b>RAHASIA - INTERNAL</b></font>', style("cls", fontSize=7.5, leading=9.5, alignment=2))],
        [Paragraph(f'<font color="white">Laporan Ancaman Siber</font>', style("title", fontName="Helvetica-Bold", fontSize=21, leading=25)), ""],
        [Paragraph(f'<font color="#cbd5e1">{_t(_period(digest))}  |  Mode {mode}  |  {_t(owner)}</font>', style("sub", fontSize=10, leading=13)), ""],
    ], colWidths=[width * 0.7, width * 0.3])
    band.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c(NAVY)),
        ("SPAN", (0, 1), (1, 1)), ("SPAN", (0, 2), (1, 2)),
        ("LEFTPADDING", (0, 0), (-1, -1), 8 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 8 * mm),
        ("TOPPADDING", (0, 0), (-1, 0), 7 * mm), ("BOTTOMPADDING", (0, -1), (-1, -1), 7 * mm),
        ("LINEBELOW", (0, -1), (-1, -1), 3, c(ACCENT)),
    ]))
    story += [band, Spacer(1, 5 * mm)]

    # ---- Metadata ----------------------------------------------------------------
    meta_rows = [
        ("Periode", _period(digest)), ("Cakupan", f"{mode}{(' - kata kunci: ' + digest['query']) if digest.get('query') else ''}"),
        ("Owner", owner), ("Dibuat", _date(digest.get("created_at", ""), with_time=True)),
        ("Model AI", f"{digest.get('provider', '')} - {digest.get('model', '')}"),
        ("Berita dianalisis", f"{digest.get('article_count', 0)} dari {digest.get('articles_in_period', digest.get('article_count', 0))} di periode ini"),
    ]
    meta = Table([
        [Paragraph(_t(meta_rows[i][0]).upper(), label), Paragraph(_t(meta_rows[i][1]), cell),
         Paragraph(_t(meta_rows[i + 1][0]).upper(), label), Paragraph(_t(meta_rows[i + 1][1]), cell)]
        for i in range(0, len(meta_rows), 2)
    ], colWidths=[24 * mm, width / 2 - 24 * mm, 26 * mm, width / 2 - 26 * mm])
    meta.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, c(LINE)),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
    ]))
    story += [meta, Spacer(1, 5 * mm)]

    # ---- KPI tiles -----------------------------------------------------------------
    tiles = [
        (kpis.get("issues", len(issues)), "Isu unik", NAVY),
        (kpis.get("critical", 0), "Isu kritis", URGENCY_COLOR["critical"]),
        (kpis.get("high", 0), "Isu tinggi", URGENCY_COLOR["high"]),
        (kpis.get("exploited", 0), "Dieksploitasi aktif", URGENCY_COLOR["critical"]),
        (kpis.get("kev", 0), "CVE di CISA KEV", ACCENT),
        (kpis.get("owners", 0), "Owner terdampak", NAVY),
    ]
    tile_w = width / len(tiles)
    kpi = Table([
        [Paragraph(f'<font color="{color}">{value}</font>', kpi_num) for value, _, color in tiles],
        [Paragraph(_t(text), kpi_lbl) for _, text, _ in tiles],
    ], colWidths=[tile_w] * len(tiles))
    kpi.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c(PANEL)),
        ("LINEAFTER", (0, 0), (-2, -1), 0.6, colors.white),
        ("TOPPADDING", (0, 0), (-1, 0), 6), ("BOTTOMPADDING", (0, -1), (-1, -1), 6),
        ("BOX", (0, 0), (-1, -1), 0.4, c(LINE)),
    ]))
    story.append(kpi)

    # ---- Executive summary, themes, priority actions --------------------------------
    story += section("Ringkasan Eksekutif")
    summary_box = Table([[Paragraph(_t(digest.get("overview")), body_j)]], colWidths=[width])
    summary_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), c("#ecfeff")), ("LINEBEFORE", (0, 0), (0, -1), 3, c(ACCENT)),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 3 * mm), ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
    ]))
    story.append(summary_box)
    if digest.get("key_themes"):
        story += [Spacer(1, 3 * mm), Paragraph("TEMA UTAMA", label), Spacer(1, 1.5),
                  Paragraph("  |  ".join(f"<b>{_t(t)}</b>" for t in digest["key_themes"]), body)]

    if digest.get("priority_actions"):
        story += section("Tindakan Prioritas")
        rows = [[Paragraph("NO", head_cell), Paragraph("TINDAKAN", head_cell)]]
        rows += [[Paragraph(str(n), cell_b), Paragraph(_t(a), cell)] for n, a in enumerate(digest["priority_actions"], start=1)]
        tbl = Table(rows, colWidths=[10 * mm, width - 10 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c(NAVY)), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c(PANEL)]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.4, c(LINE)),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)

    # ---- Issue overview ---------------------------------------------------------------
    if issues:
        story += section("Ikhtisar Isu")
        story.append(Paragraph(_t(f"{len(issues)} isu dari {kpis.get('articles', len(digest.get('articles', [])))} berita. "
                                  "Berita tentang cerita yang sama (CVE atau nama kampanye yang sama) digabung menjadi satu isu."), small))
        story.append(Spacer(1, 2))
        rows = [[Paragraph(h, head_cell) for h in ("#", "URGENSI", "ISU", "PRODUK / OWNER", "CVE", "SUMBER")]]
        for n, issue in enumerate(issues, start=1):
            rows.append([
                Paragraph(str(n), cell_b), badge(issue["urgency"]),
                Paragraph(f"<b>{_t(issue['title'])}</b><br/><font color='{MUTED}' size='7'>{_t(EXPLOIT_LABEL.get(issue['exploitation'], ''))}</font>", cell),
                Paragraph(products_markup(issue), style("cell_s", fontSize=7.6, leading=10)),
                Paragraph(cve_markup(issue), style("cell_c", fontSize=7.4, leading=9.8)),
                Paragraph(str(len(issue["sources"])), cell),
            ])
        tbl = Table(rows, colWidths=[7 * mm, 19 * mm, 62 * mm, 45 * mm, width - 147 * mm, 14 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c(NAVY)), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c(PANEL)]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (5, 1), (5, -1), "CENTER"), ("ALIGN", (0, 1), (0, -1), "CENTER"),
            ("BOX", (0, 0), (-1, -1), 0.4, c(LINE)), ("LINEBELOW", (0, 1), (-1, -1), 0.3, c(LINE)),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(tbl)

    # ---- Owner impact ------------------------------------------------------------------
    impact = digest.get("owner_impact", [])
    if impact:
        story += section("Dampak per Owner")
        rows = [[Paragraph(h, head_cell) for h in ("OWNER", "KRITIS", "TINGGI", "LAIN", "ISU", "PRODUK TERDAMPAK")]]
        for r in impact:
            def num(value, color):
                return Paragraph(f'<font color="{color if value else LINE}"><b>{value}</b></font>', style("num", fontSize=9, alignment=TA_CENTER))
            rows.append([
                Paragraph(f"<b>{_t(r['owner'])}</b>", cell),
                num(r["critical"], URGENCY_COLOR["critical"]), num(r["high"], URGENCY_COLOR["high"]), num(r["other"], INK),
                Paragraph(_t(", ".join(f"#{i}" for i in r["issues"])), cell),
                Paragraph(_t(", ".join(r["products"])), style("cell_p", fontSize=7.6, leading=10)),
            ])
        tbl = Table(rows, colWidths=[30 * mm, 15 * mm, 15 * mm, 13 * mm, 30 * mm, width - 103 * mm], repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c(NAVY)), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c(PANEL)]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.4, c(LINE)),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)

    # ---- Issue detail cards ---------------------------------------------------------------
    if issues:
        story += section("Rincian Isu")
    for n, issue in enumerate(issues, start=1):
        color = URGENCY_COLOR.get(issue["urgency"], MUTED)
        header = Table([[badge(issue["urgency"]),
                         Paragraph(f'<font color="{MUTED}"><b>ISU #{n}</b>  |  {_t(EXPLOIT_LABEL.get(issue["exploitation"], ""))}'
                                   f'  |  pertama dilaporkan {_t(_date(issue.get("first_seen", "")))}</font>', style("hdr", fontSize=7.6, leading=10))]],
                       colWidths=[19 * mm, None])
        header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        content: List[Any] = [header, Spacer(1, 3), Paragraph(_t(issue["title"]), card_title), Spacer(1, 2),
                              Paragraph(_t(issue.get("summary")), body_j), Spacer(1, 4)]

        facts = Table([
            [Paragraph("PRODUK / OWNER", label), Paragraph(products_markup(issue), cell)],
            [Paragraph("CVE", label), Paragraph(cve_markup(issue), cell)],
        ], colWidths=[28 * mm, None])
        facts.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (-1, -1), c(PANEL)),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        content += [facts, Spacer(1, 4)]

        if issue.get("recommended_actions"):
            content.append(Paragraph("REKOMENDASI", label))
            content += [Paragraph(f"<b>{i}.</b> {_t(a)}", style("act", fontSize=8.6, leading=12, leftIndent=9, firstLineIndent=-9))
                        for i, a in enumerate(issue["recommended_actions"], start=1)]
            content.append(Spacer(1, 4))

        content.append(Paragraph(f"SUMBER ({len(issue['sources'])})", label))
        for s in issue["sources"]:
            link = s.get("link") or ""
            title = f'<link href="{_t(link)}" color="{ACCENT}">{_t(s.get("title") or link)}</link>' if link.startswith(("http://", "https://")) else _t(s.get("title"))
            content.append(Paragraph(f"{_t(s.get('source', ''))}  |  {_t(_date(s.get('published_at', '')))}  -  {title}",
                                     style("src", fontSize=7.6, leading=10.2, textColor=c(MUTED))))

        card = Table([["", content]], colWidths=[2.2 * mm, width - 2.2 * mm], splitInRow=1)
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), c(color)),
            ("BOX", (0, 0), (-1, -1), 0.5, c(LINE)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (1, 0), (1, -1), 4 * mm), ("RIGHTPADDING", (1, 0), (1, -1), 4 * mm),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5 * mm), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5 * mm),
        ]))
        # Keep a card on one page when it fits; very long cards still split between rows of their content.
        story += [KeepTogether([card]), Spacer(1, 4 * mm)]

    # ---- Methodology ------------------------------------------------------------------------
    story += section("Metodologi & Catatan")
    notes = [
        "Berita dikumpulkan dari feed RSS (The Hacker News, BleepingComputer, CISA, Krebs on Security) dan dicocokkan "
        "dengan list critical tools secara lokal di server LazySOC.",
        "Ringkasan, urgensi, dan rekomendasi dibuat otomatis oleh model AI hanya dari teks berita publik. Data owner, "
        "versi, dan hostname tidak dikirim ke model. Verifikasi detail teknis ke sumber asli sebelum bertindak.",
        "Urgensi: KRITIS = dieksploitasi aktif / wormable pada produk yang terekspos internet; TINGGI = isu serius dengan "
        "patch tersedia; SEDANG = perlu ditinjau; RENDAH = berita umum. (KEV) = CVE tercantum di katalog CISA Known Exploited Vulnerabilities.",
        "Kecocokan 'vendor saja' berarti vendor disebut tetapi produk spesifiknya tidak ada di list critical tools.",
        "Dokumen ini RAHASIA karena memuat pemetaan produk ke owner/customer. Jangan dibagikan ke luar tim.",
    ]
    story += [Paragraph(f"<b>{i}.</b> {_t(n)}", style("note", fontSize=8, leading=11, leftIndent=9, firstLineIndent=-9, textColor=c(MUTED)))
              for i, n in enumerate(notes, start=1)]

    # ---- Page chrome (header from page 2, footer with "x dari y") ---------------------------------
    period_text = _period(digest)

    class NumberedCanvas(rl_canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._pages = []

        def showPage(self):
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._pages)
            for state in self._pages:
                self.__dict__.update(state)
                self._chrome(total)
                super().showPage()
            super().save()

        def _chrome(self, total):
            self.saveState()
            if self._pageNumber > 1:
                self.setFillColor(c(NAVY))
                self.rect(0, page_h - 10 * mm, page_w, 10 * mm, stroke=0, fill=1)
                self.setFillColor(colors.white)
                self.setFont("Helvetica-Bold", 7.5)
                self.drawString(margin, page_h - 6.3 * mm, "LAZYSOC THREAT DIGEST")
                self.setFont("Helvetica", 7.5)
                self.drawString(margin + 38 * mm, page_h - 6.3 * mm, period_text.encode("cp1252", "replace").decode("cp1252"))
                self.drawRightString(page_w - margin, page_h - 6.3 * mm, "RAHASIA - INTERNAL")
            self.setStrokeColor(c(LINE))
            self.setLineWidth(0.5)
            self.line(margin, 12 * mm, page_w - margin, 12 * mm)
            self.setFillColor(c(MUTED))
            self.setFont("Helvetica", 7)
            self.drawString(margin, 8 * mm, "Dibuat otomatis oleh LazySOC - verifikasi ke sumber asli sebelum bertindak.")
            self.drawRightString(page_w - margin, 8 * mm, f"Halaman {self._pageNumber} dari {total}")
            self.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=margin, rightMargin=margin, topMargin=16 * mm, bottomMargin=17 * mm,
                            title=f"LazySOC Threat Digest {period_text}", author="LazySOC", subject="Threat intelligence digest")
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
