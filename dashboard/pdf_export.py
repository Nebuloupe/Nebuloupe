"""
dashboard/pdf_export.py
Generates a professional PDF security report using fpdf.
"""

from fpdf import FPDF
from datetime import datetime, timezone


# ── Colour Palette ────────────────────────────────────────────────────────────

SEV_COLORS = {
    "Critical": (248,  81,  73),
    "High":     (227, 112,  59),
    "Medium":   (227, 179,  65),
    "Low":      ( 63, 185,  80),
}

BG      = (  8,  11,  16)
SURFACE = ( 13,  17,  23)
BORDER  = ( 33,  38,  45)
TEXT    = (201, 209, 217)
MUTED   = (139, 148, 158)
ACCENT  = (  0, 224, 150)

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


# ── Report Class ──────────────────────────────────────────────────────────────

class _Report(FPDF):

    HEADER_H = 20   # header bar height in mm — content starts below this

    def __init__(self, meta: dict, summary: dict) -> None:
        super().__init__(orientation="L", unit="mm", format="A4")
        self.meta    = meta
        self.summary = summary
        # top margin must exceed header height so content never overlaps
        self.set_margins(14, self.HEADER_H + 4, 14)
        self.set_auto_page_break(auto=True, margin=16)

    # ── Colour Helpers ────────────────────────────────────────────────────────

    def _rgb(self, r: int, g: int, b: int) -> None:
        self.set_text_color(r, g, b)

    def _fill(self, r: int, g: int, b: int) -> None:
        self.set_fill_color(r, g, b)

    def _draw(self, r: int, g: int, b: int) -> None:
        self.set_draw_color(r, g, b)

    def _sev_color(self, severity: str) -> tuple:
        return SEV_COLORS.get(severity, MUTED)

    # ── Header & Footer ───────────────────────────────────────────────────────

    def header(self) -> None:
        # Dark background bar
        self._fill(*BG)
        self.rect(0, 0, 297, self.HEADER_H, "F")

        # Thin accent border along the bottom of the bar
        self._draw(*ACCENT)
        self.set_line_width(0.3)
        self.line(0, self.HEADER_H, 297, self.HEADER_H)

        # Logo / title text
        self.set_font("Helvetica", "B", 12)
        self._rgb(*ACCENT)
        self.set_xy(14, 5)
        self.cell(120, 10, "NEBULOUPE  \xb7  Cloud Security Report", ln=0)

        # Scan ID — right-aligned
        self.set_font("Helvetica", "", 7)
        self._rgb(*MUTED)
        self.set_xy(160, 7)
        self.cell(123, 6, f"Scan ID: {self.meta.get('scan_id', '')}", align="R")

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self._rgb(*MUTED)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 6, f"Generated {ts}  \xb7  Page {self.page_no()}", align="C")

    # ── Section Title ─────────────────────────────────────────────────────────

    def section_title(self, title: str) -> None:
        self.ln(2)
        self._fill(*SURFACE)
        self._draw(*BORDER)
        self.set_font("Helvetica", "B", 9)
        self._rgb(*ACCENT)
        self.set_x(14)
        self.cell(0, 8, f"  {title.upper()}", border=1, fill=True, ln=1)
        self.ln(3)

    # ── Cover Page ────────────────────────────────────────────────────────────

    def cover_page(self) -> None:
        self.add_page()

        # Page background (below the header bar)
        self._fill(*BG)
        self.rect(0, self.HEADER_H, 297, 210 - self.HEADER_H, "F")

        # Main title
        self.set_font("Helvetica", "B", 32)
        self._rgb(*ACCENT)
        self.set_xy(0, 55)
        self.cell(0, 16, "NEBULOUPE", align="C", ln=1)

        # Subtitle
        self.set_font("Helvetica", "", 13)
        self._rgb(*MUTED)
        self.cell(0, 8, "Multi-Cloud Security Scan Report", align="C", ln=1)

        # Decorative divider
        self.ln(8)
        self._draw(*ACCENT)
        self.set_line_width(0.5)
        self.line(80, self.get_y(), 217, self.get_y())
        self.ln(8)

        # ── Scan Metadata ─────────────────────────────────────────────────────
        scope   = self.meta.get("cloud_scope", "").upper()
        account = self.meta.get("target_account", "N/A")
        status  = self.meta.get("status", "N/A").upper()
        dur     = f"{self.meta.get('scan_duration_seconds', 0)}s"
        ts_raw  = self.meta.get("scan_started_at", "")
        ts      = (ts_raw[:19].replace("T", " ") + " UTC") if ts_raw else "N/A"

        meta_rows = [
            ("Cloud Scope",  scope),
            ("Account",      account),
            ("Scan Status",  status),
            ("Duration",     dur),
            ("Timestamp",    ts),
        ]

        for label, value in meta_rows:
            self.set_x(80)
            self.set_font("Helvetica", "", 9)
            self._rgb(*MUTED)
            self.cell(50, 7, label, ln=0)

            self.set_font("Helvetica", "B", 9)
            self._rgb(*TEXT)
            self.cell(0, 7, value, ln=1)

        # ── Severity Pills ────────────────────────────────────────────────────
        self.ln(8)

        sc = self.summary.get("severity_counts", {})
        pills = [
            ("TOTAL",    str(self.summary.get("total_findings", 0)), TEXT),
            ("CRITICAL", str(sc.get("Critical", 0)),                 SEV_COLORS["Critical"]),
            ("HIGH",     str(sc.get("High",     0)),                 SEV_COLORS["High"]),
            ("MEDIUM",   str(sc.get("Medium",   0)),                 SEV_COLORS["Medium"]),
            ("LOW",      str(sc.get("Low",      0)),                 SEV_COLORS["Low"]),
        ]

        pill_w  = 38
        gap     = 4
        total_w = pill_w * len(pills) + gap * (len(pills) - 1)
        start_x = (297 - total_w) / 2
        y       = self.get_y()

        for i, (label, value, color) in enumerate(pills):
            x = start_x + i * (pill_w + gap)

            # Pill background + border
            self._fill(*SURFACE)
            self._draw(*color)
            self.set_line_width(0.4)
            self.rect(x, y, pill_w, 20, "FD")

            # Large count
            self.set_font("Helvetica", "B", 16)
            self._rgb(*color)
            self.set_xy(x, y + 2)
            self.cell(pill_w, 8, value, align="C")

            # Label beneath count
            self.set_font("Helvetica", "", 7)
            self._rgb(*MUTED)
            self.set_xy(x, y + 12)
            self.cell(pill_w, 5, label, align="C")

    # ── Findings Table ────────────────────────────────────────────────────────

    def findings_table(self, findings: list) -> None:
        self.add_page()
        self.section_title("Detailed Findings")

        headers = ["SEV",  "CLOUD", "RULE ID", "CHECK",  "RESOURCE ID", "REGION", "CATEGORY", "STATUS"]
        widths  = [ 18,     18,      22,        70,       40,            22,       28,          16     ]

        # Table header row
        self._fill(*SURFACE)
        self._draw(*BORDER)
        self.set_font("Helvetica", "B", 7)
        self._rgb(*MUTED)
        self.set_x(14)

        for heading, width in zip(headers, widths):
            self.cell(width, 6, heading, border=1, fill=True, align="C")
        self.ln()

        # Data rows
        self.set_font("Helvetica", "", 7)

        for i, finding in enumerate(findings):
            sev     = finding.get("severity", "Unknown")
            status  = finding.get("status",   "FAIL")
            color   = self._sev_color(sev)
            fill_bg = (16, 20, 26) if i % 2 == 0 else (13, 17, 23)

            self._fill(*fill_bg)
            self._draw(*BORDER)

            values = [
                sev,
                finding.get("cloud_provider", "N/A").upper(),
                finding.get("rule_id",        "N/A"),
                finding.get("check",          "N/A")[:55],
                finding.get("resource_id",    "N/A")[:28],
                finding.get("region",         "global"),
                finding.get("category",       "N/A"),
                status,
            ]

            self.set_x(14)

            for col_idx, (value, width) in enumerate(zip(values, widths)):
                if col_idx == 0:
                    # Severity column — coloured + bold
                    self._rgb(*color)
                    self.set_font("Helvetica", "B", 7)

                elif col_idx == len(values) - 1:
                    # Status column — red for FAIL, green otherwise
                    if status == "FAIL":
                        self._rgb(248, 81, 73)
                    else:
                        self._rgb(63, 185, 80)
                    self.set_font("Helvetica", "B", 7)

                else:
                    self._rgb(*TEXT)
                    self.set_font("Helvetica", "", 7)

                self.cell(width, 5.5, str(value), border=1, fill=True)

            self.ln()

    # ── Recommendations Page ──────────────────────────────────────────────────

    def recommendations_page(self, findings: list) -> None:
        self.add_page()
        self.section_title("Top Recommendations")

        # Collect up to 15 unique failed rules
        seen = set()
        recs = []
        for finding in findings:
            rule_id = finding.get("rule_id", "")
            if rule_id not in seen and finding.get("status") == "FAIL":
                seen.add(rule_id)
                recs.append(finding)
            if len(recs) >= 15:
                break

        for idx, finding in enumerate(recs, start=1):
            color = self._sev_color(finding.get("severity", "Unknown"))

            # Numbered badge
            self._fill(*color)
            self.set_font("Helvetica", "B", 8)
            self._rgb(*BG)
            self.set_x(14)
            self.cell(6, 6, str(idx), fill=True, align="C")

            # Check name
            self.set_font("Helvetica", "B", 8)
            self._rgb(*TEXT)
            self.cell(0, 6, f"  {finding.get('check', 'N/A')}", ln=1)

            # Description
            self.set_x(22)
            self.set_font("Helvetica", "", 7)
            self._rgb(*MUTED)
            self.multi_cell(0, 4.5, finding.get("description", ""))
            self.ln(1)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf_report(results: dict) -> bytes:
    """Build the full security report and return raw PDF bytes."""
    meta     = results.get("scan_metadata", {})
    summary  = results.get("summary",       {})
    findings = results.get("findings",      [])

    sev_rank = {sev: i for i, sev in enumerate(SEV_ORDER)}
    findings = sorted(
        findings,
        key=lambda f: sev_rank.get(f.get("severity", "Low"), 4),
    )

    pdf = _Report(meta, summary)
    pdf.cover_page()
    pdf.findings_table(findings)
    pdf.recommendations_page(findings)

    return pdf.output(dest="S").encode("latin-1")