"""
dashboard/pdf/cover.py
Cover page rendering — full-bleed hero, scan metadata card, severity pills.
"""

from .base import (
    ReportBase, SEV_COLORS, BG, SURFACE, SURFACE2, BORDER, TEXT, MUTED, ACCENT
)
from dashboard.icons import draw_cloud_icon_pdf


def render_cover(pdf: ReportBase) -> None:
    """Draw the full-bleed cover page onto `pdf`."""
    pdf.add_page()  # page 1 — header() sees page_no()==1, paints BG only

    PW, PH = pdf.PAGE_W, pdf.PAGE_H

    # Left accent stripe
    pdf._fill(*ACCENT)
    pdf.rect(0, 0, 4, PH, "F")

    # Thin top bar
    pdf._fill(*SURFACE2)
    pdf.rect(4, 0, PW - 4, 2, "F")

    # Vertical letters in stripe
    pdf.set_font("Helvetica", "B", 7)
    pdf._rgb(*BG)
    for ci, ch in enumerate("NEBULOUPE"):
        pdf.set_xy(0.3, 10 + ci * 5)
        pdf.cell(3.4, 4.5, ch, align="C", ln=0)

    # ── Hero ─────────────────────────────────────────────────────────────────
    # Cloud icon centred above the title
    icon_size = 18
    icon_x    = (PW - icon_size) / 2
    draw_cloud_icon_pdf(pdf, pdf._cloud.lower(), icon_x, 18, size=icon_size)

    pdf.set_font("Helvetica", "B", 44)
    pdf._rgb(*ACCENT)
    pdf.set_xy(0, 38)
    pdf.cell(PW, 20, "NEBULOUPE", align="C", ln=1)

    pdf.set_font("Helvetica", "", 13)
    pdf._rgb(*MUTED)
    pdf.cell(PW, 8, "Cloud Misconfiguration Security Scanner Report", align="C", ln=1)

    pdf.ln(4)
    pdf._draw(*ACCENT)
    pdf.set_line_width(0.7)
    cx = PW / 2
    pdf.line(cx - 70, pdf.get_y(), cx + 70, pdf.get_y())
    pdf.ln(7)

    # ── Scan metadata card ────────────────────────────────────────────────────
    card_w = 180
    card_x = (PW - card_w) / 2
    card_y = pdf.get_y()
    row_h  = 8
    lbl_w  = 55

    meta_rows = [
        ("Cloud Provider", pdf._cloud),
        ("Account ID",     pdf._account),
        ("Scan Status",    pdf.meta.get("status", "N/A").upper()),
        ("Duration",       pdf._duration),
        ("Date",           pdf._date),
        ("Time",           pdf._time),
    ]

    card_total_h = len(meta_rows) * row_h + 6
    pdf._fill(*SURFACE)
    pdf._draw(*BORDER)
    pdf.set_line_width(0.3)
    pdf.rect(card_x, card_y, card_w, card_total_h, "FD")

    # Card header bar
    pdf._fill(*SURFACE2)
    pdf.rect(card_x, card_y, card_w, 6, "F")
    pdf.set_font("Helvetica", "B", 6.5)
    pdf._rgb(*ACCENT)
    pdf.set_xy(card_x + 4, card_y + 1)
    pdf.cell(card_w - 8, 4, "SCAN DETAILS", ln=0)

    for row_idx, (label, value) in enumerate(meta_rows):
        ry = card_y + 6 + row_idx * row_h
        if row_idx > 0:
            pdf._draw(*BORDER)
            pdf.set_line_width(0.15)
            pdf.line(card_x + 2, ry, card_x + card_w - 2, ry)

        pdf.set_font("Helvetica", "", 7.5)
        pdf._rgb(*MUTED)
        pdf.set_xy(card_x + 4, ry + 1)
        pdf.cell(lbl_w, row_h - 2, label, ln=0)

        pdf.set_font("Helvetica", "B", 8)
        pdf._rgb(*TEXT)
        pdf.set_xy(card_x + lbl_w + 2, ry + 1)
        pdf.cell(card_w - lbl_w - 4, row_h - 2, value, ln=0)

    # ── Severity pills ────────────────────────────────────────────────────────
    sc = pdf.summary.get("severity_counts", {})
    pills = [
        ("TOTAL",    str(pdf.summary.get("total_findings", 0)), TEXT),
        ("CRITICAL", str(sc.get("Critical", 0)),                SEV_COLORS["Critical"]),
        ("HIGH",     str(sc.get("High",     0)),                SEV_COLORS["High"]),
        ("MEDIUM",   str(sc.get("Medium",   0)),                SEV_COLORS["Medium"]),
        ("LOW",      str(sc.get("Low",      0)),                SEV_COLORS["Low"]),
    ]

    pill_w  = 38
    pill_h  = 24
    gap     = 5
    total_w = pill_w * len(pills) + gap * (len(pills) - 1)
    pill_x0 = (PW - total_w) / 2
    pill_y  = PH - pill_h - 14

    for i, (label, value, color) in enumerate(pills):
        px = pill_x0 + i * (pill_w + gap)
        pdf._fill(*SURFACE)
        pdf._draw(*color)
        pdf.set_line_width(0.5)
        pdf.rect(px, pill_y, pill_w, pill_h, "FD")
        pdf._fill(*color)
        pdf.rect(px, pill_y, pill_w, 3, "F")
        pdf.set_font("Helvetica", "B", 16)
        pdf._rgb(*color)
        pdf.set_xy(px, pill_y + 4)
        pdf.cell(pill_w, 9, value, align="C")
        pdf.set_font("Helvetica", "", 6.5)
        pdf._rgb(*MUTED)
        pdf.set_xy(px, pill_y + 15)
        pdf.cell(pill_w, 5, label, align="C")

    # Scan ID footnote
    pdf.set_font("Helvetica", "", 6.5)
    pdf._rgb(*MUTED)
    pdf.set_xy(0, PH - 7)
    pdf.cell(PW, 5, f"Scan ID: {pdf._scan_id}", align="C")
