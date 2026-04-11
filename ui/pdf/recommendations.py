"""
dashboard/pdf/recommendations.py
Recommendations page — top 15 unique failed rules with descriptions.
"""

from .base import ReportBase, SURFACE, BG, TEXT, MUTED


def render_recommendations(pdf: ReportBase, findings: list) -> None:
    """Render the top recommendations onto a new page."""
    pdf.add_page()
    pdf.section_title("Top Recommendations")

    # Collect up to 15 unique failed rules
    seen, recs = set(), []
    for f in findings:
        rid = f.get("rule_id", "")
        if rid not in seen and f.get("status") == "FAIL":
            seen.add(rid)
            recs.append(f)
        if len(recs) >= 15:
            break

    for idx, finding in enumerate(recs, start=1):
        color = pdf._sev_color(finding.get("severity", "Unknown"))

        # Numbered badge
        pdf._fill(*color)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf._rgb(*BG)
        pdf.set_x(pdf.MARGIN)
        pdf.cell(6, 6.5, str(idx), fill=True, align="C")

        # Severity label
        pdf._fill(*SURFACE)
        pdf._rgb(*color)
        pdf.set_font("Helvetica", "B", 6.5)
        pdf.cell(18, 6.5, finding.get("severity", "").upper(), fill=True, align="C", border=1)

        # Check name
        pdf.set_font("Helvetica", "B", 7.5)
        pdf._rgb(*TEXT)
        pdf.cell(0, 6.5, f"  {finding.get('check', 'N/A')}", ln=1)

        # Description
        pdf.set_x(pdf.MARGIN + 8)
        pdf.set_font("Helvetica", "", 6.5)
        pdf._rgb(*MUTED)
        pdf.multi_cell(0, 4, finding.get("description", "\u2014"))
        pdf.ln(0.5)
