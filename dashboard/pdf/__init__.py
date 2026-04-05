"""
dashboard/pdf/__init__.py
Public API — generate_pdf_report() assembles all pages.
"""

from .base import ReportBase, SEV_ORDER
from .cover import render_cover
from .findings import render_findings
from .recommendations import render_recommendations


def generate_pdf_report(results: dict) -> bytes:
    """Build the full security report and return raw PDF bytes."""
    meta     = results.get("scan_metadata", {})
    summary  = results.get("summary",       {})
    findings = results.get("findings",      [])

    # Sort findings by severity
    sev_rank = {sev: i for i, sev in enumerate(SEV_ORDER)}
    findings = sorted(findings, key=lambda f: sev_rank.get(f.get("severity", "Low"), 4))

    pdf = ReportBase(meta, summary)

    render_cover(pdf)
    render_findings(pdf, findings)
    render_recommendations(pdf, findings)

    return pdf.output(dest="S").encode("latin-1")
