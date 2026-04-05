"""
dashboard/pdf/base.py
Base PDF class — colours, helpers, header, footer, section title.
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

BG       = (  8,  11,  16)
SURFACE  = ( 13,  17,  23)
SURFACE2 = ( 20,  25,  33)
BORDER   = ( 33,  38,  45)
TEXT     = (201, 209, 217)
MUTED    = (139, 148, 158)
ACCENT   = (  0, 224, 150)

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_duration(seconds: float) -> str:
    if seconds == 0:  return "< 1s"
    if seconds < 1:   return f"{seconds:.2f}s"
    if seconds < 60:  return f"{seconds:.1f}s"
    m, s = int(seconds // 60), int(seconds % 60)
    return f"{m}m {s:02d}s"


def fmt_timestamp(raw: str):
    if not raw:
        return "N/A", "N/A"
    try:
        from datetime import timedelta
        IST = timezone(timedelta(hours=5, minutes=30))
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(IST)
        return dt.strftime("%Y-%m-%d"), dt.strftime("%H:%M:%S IST")
    except ValueError:
        c = raw[:19].replace("T", " ")
        return c[:10], c[11:] + " IST"


# ── Base Report Class ─────────────────────────────────────────────────────────

class ReportBase(FPDF):

    PAGE_W   = 297
    PAGE_H   = 210
    ROW1_H   = 12
    ROW2_H   = 11
    HEADER_H = ROW1_H + ROW2_H   # 23 mm
    TOP_PAD  = 10
    MARGIN   = 14

    def __init__(self, meta: dict, summary: dict) -> None:
        super().__init__(orientation="L", unit="mm", format="A4")
        self.meta    = meta
        self.summary = summary

        self._cloud    = meta.get("cloud_scope", "N/A").upper()
        self._account  = meta.get("account_id", meta.get("target_account", "N/A"))
        self._duration = fmt_duration(meta.get("scan_duration_seconds", 0))
        self._date, self._time = fmt_timestamp(meta.get("scan_started_at", ""))
        self._scan_id  = meta.get("scan_id", "")
        self._is_cover = False

        self._top_margin = self.HEADER_H + self.TOP_PAD
        self.set_margins(self.MARGIN, self._top_margin, self.MARGIN)
        self.set_auto_page_break(auto=True, margin=18)

    # ── Colour helpers ────────────────────────────────────────────────────────

    def _rgb(self, r, g, b):   self.set_text_color(r, g, b)
    def _fill(self, r, g, b):  self.set_fill_color(r, g, b)
    def _draw(self, r, g, b):  self.set_draw_color(r, g, b)
    def _sev_color(self, sev): return SEV_COLORS.get(sev, MUTED)

    # ── Header ────────────────────────────────────────────────────────────────

    def header(self) -> None:
        self._fill(*BG)
        self.rect(0, 0, self.PAGE_W, self.PAGE_H, "F")

        if self._is_cover:
            return

        pw = self.PAGE_W

        # Row 1 — brand bar
        self._fill(*BG)
        self.rect(0, 0, pw, self.ROW1_H, "F")
        self._fill(*ACCENT)
        self.rect(0, 0, 3, self.ROW1_H, "F")

        self.set_font("Helvetica", "B", 11)
        self._rgb(*ACCENT)
        self.set_xy(7, 2)
        self.cell(80, 8, "NEBULOUPE", ln=0)

        self.set_font("Helvetica", "", 8)
        self._rgb(*MUTED)
        self.set_xy(42, 3.5)
        self.cell(80, 5, "Multi-Cloud Security Report", ln=0)

        self.set_font("Helvetica", "", 7)
        self._rgb(*MUTED)
        self.set_xy(pw - 100, 4)
        self.cell(100 - self.MARGIN, 5, f"Scan ID: {self._scan_id}", align="R", ln=0)

        self._draw(*ACCENT)
        self.set_line_width(0.3)
        self.line(0, self.ROW1_H, pw, self.ROW1_H)

        # Row 2 — info bar
        y2 = self.ROW1_H
        self._fill(*SURFACE2)
        self.rect(0, y2, pw, self.ROW2_H, "F")

        labels = ["CLOUD PROVIDER", "ACCOUNT ID",    "SCAN DURATION", "SCAN DATE",   "SCAN TIME"]
        values = [self._cloud,       self._account,   self._duration,  self._date,    self._time]
        col_w  = pw / len(labels)

        for i, (lbl, val) in enumerate(zip(labels, values)):
            x = i * col_w
            if i > 0:
                self._draw(*BORDER)
                self.set_line_width(0.2)
                self.line(x, y2 + 1, x, y2 + self.ROW2_H - 1)

            self.set_font("Helvetica", "", 6)
            self._rgb(*MUTED)
            self.set_xy(x + 4, y2 + 1.2)
            self.cell(col_w - 8, 4, lbl, ln=0)

            self.set_font("Helvetica", "B", 8.5)
            self._rgb(*TEXT)
            self.set_xy(x + 4, y2 + 5.5)
            self.cell(col_w - 8, 5, val, ln=0)

        self._draw(*BORDER)
        self.set_line_width(0.4)
        self.line(0, y2 + self.ROW2_H, pw, y2 + self.ROW2_H)

        self.set_xy(self.MARGIN, self._top_margin)

    # ── Footer ────────────────────────────────────────────────────────────────

    def footer(self) -> None:
        if self._is_cover:
            return
        self.set_y(-11)
        self.set_font("Helvetica", "", 6.5)
        self._rgb(*MUTED)
        self.set_x(self.MARGIN)
        self.cell(0, 5, f"CONFIDENTIAL  \xb7  {self._account}  \xb7  {self._cloud}", align="L", ln=0)
        self.set_x(0)
        self.cell(self.PAGE_W, 5, f"Page {self.page_no() - 1}", align="C", ln=0)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.set_x(0)
        self.cell(self.PAGE_W - self.MARGIN, 5, f"Generated {ts}", align="R")

    # ── Section Title ─────────────────────────────────────────────────────────

    def section_title(self, title: str) -> None:
        self.ln(2)
        self._fill(*ACCENT)
        self.rect(self.MARGIN, self.get_y(), 2, 7, "F")
        self._fill(*SURFACE)
        self._draw(*BORDER)
        self.set_line_width(0.3)
        self.set_x(self.MARGIN + 2)
        self.set_font("Helvetica", "B", 8.5)
        self._rgb(*ACCENT)
        self.cell(self.PAGE_W - 2 * self.MARGIN - 2, 7,
                  f"   {title.upper()}", border="LRB", fill=True, ln=1)
        self.ln(3)
