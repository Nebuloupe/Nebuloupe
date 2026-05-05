"""
dashboard/pdf/__init__.py
Public API — generate_pdf_report() assembles all pages.
"""

from .base import ReportBase, SEV_ORDER
from .cover import render_cover
from .findings import render_findings
from .recommendations import render_recommendations


_UNICODE_REPLACEMENTS = {
    "\u2013": "-",   # en dash
    "\u2014": "-",   # em dash
    "\u2018": "'",   # left single quote
    "\u2019": "'",   # right single quote
    "\u201c": '"',   # left double quote
    "\u201d": '"',   # right double quote
    "\u2022": "-",   # bullet
    "\u2026": "...", # ellipsis
    "\u00a0": " ",   # non-breaking space
}


def _latin1_safe(text: str) -> str:
    """Convert unicode punctuation/symbols to latin-1-safe text for FPDF."""
    if not isinstance(text, str):
        return text

    for src, dst in _UNICODE_REPLACEMENTS.items():
        text = text.replace(src, dst)

    return text.encode("latin-1", "replace").decode("latin-1")


def _sanitize_obj(value):
    """Recursively sanitize strings inside nested report objects."""
    if isinstance(value, dict):
        return {k: _sanitize_obj(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_obj(v) for v in value]
    if isinstance(value, str):
        return _latin1_safe(value)
    return value


def generate_pdf_report(results: dict) -> bytes:
    """Build the full security report and return raw PDF bytes."""
    meta     = _sanitize_obj(results.get("scan_metadata", {}))
    summary  = _sanitize_obj(results.get("summary",       {}))
    findings = _sanitize_obj(results.get("findings",      []))

    # Sort findings by severity
    sev_rank = {sev: i for i, sev in enumerate(SEV_ORDER)}
    findings = sorted(findings, key=lambda f: sev_rank.get(f.get("severity", "Low"), 4))

    pdf = ReportBase(meta, summary)

    render_cover(pdf)
    render_findings(pdf, findings)
    render_recommendations(pdf, findings)

    return pdf.output(dest="S").encode("latin-1", "replace")
