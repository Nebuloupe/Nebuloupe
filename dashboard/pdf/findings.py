"""
dashboard/pdf/findings.py
Findings table page — detailed findings sorted by severity.
"""

from .base import ReportBase, SEV_COLORS, SURFACE, BORDER, TEXT, MUTED


def render_findings(pdf: ReportBase, findings: list) -> None:
    """Render the detailed findings table onto a new page."""
    # Suppress footer for the cover page transition, but let header render normally.
    pdf._is_cover        = False
    pdf._suppress_footer = True   # skip footer() when add_page closes the cover
    pdf.add_page()
    pdf._suppress_footer = False  # restore for all subsequent pages
    pdf.section_title("Detailed Findings")

    headers = ["SEV",  "CLOUD", "RULE ID", "CHECK",  "RESOURCE ID", "REGION", "CATEGORY", "STATUS"]
    widths  = [ 18,     20,      24,        68,       40,            24,       28,          18     ]

    # Table header row
    pdf._fill(*SURFACE)
    pdf._draw(*BORDER)
    pdf.set_font("Helvetica", "B", 6.5)
    pdf._rgb(*MUTED)
    pdf.set_x(pdf.MARGIN)
    for h, w in zip(headers, widths):
        pdf.cell(w, 6.5, h, border=1, fill=True, align="C")
    pdf.ln()

    # Data rows
    for i, finding in enumerate(findings):
        sev     = finding.get("severity", "Unknown")
        status  = finding.get("status",   "FAIL")
        color   = pdf._sev_color(sev)
        fill_bg = (16, 20, 27) if i % 2 == 0 else SURFACE

        pdf._fill(*fill_bg)
        pdf._draw(*BORDER)

        values = [
            sev,
            finding.get("cloud_provider", "N/A").upper(),
            finding.get("rule_id",        "N/A"),
            finding.get("check",          "N/A")[:52],
            finding.get("resource_id",    "N/A")[:26],
            finding.get("region",         "global"),
            finding.get("category",       "N/A"),
            status,
        ]

        pdf.set_x(pdf.MARGIN)
        for col_idx, (value, width) in enumerate(zip(values, widths)):
            if col_idx == 0:
                pdf._rgb(*color)
                pdf.set_font("Helvetica", "B", 6.5)
            elif col_idx == len(values) - 1:
                pdf._rgb(248, 81, 73) if status == "FAIL" else pdf._rgb(63, 185, 80)
                pdf.set_font("Helvetica", "B", 6.5)
            else:
                pdf._rgb(*TEXT)
                pdf.set_font("Helvetica", "", 6.5)
            pdf.cell(width, 5.5, str(value), border=1, fill=True)
        pdf.ln()
