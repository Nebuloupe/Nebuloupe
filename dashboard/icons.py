"""
dashboard/icons.py
Cloud provider icons — SVG strings for HTML/dashboard use,
and base64-encoded PNG bytes for PDF embedding.
"""

import base64
import io

# ── SVG Icons (for HTML / landing page) ──────────────────────────────────────

SVG_ICONS = {
    "aws": """<svg viewBox="0 0 80 48" width="56" height="34" xmlns="http://www.w3.org/2000/svg">
  <path d="M22.9 19.7c0 .8.1 1.5.3 2 .2.6.5 1.2.9 1.8.1.2.2.4.2.6 0 .3-.2.5-.5.7l-1.6 1.1c-.2.1-.4.2-.6.2-.3 0-.5-.1-.8-.4-.4-.4-.7-.9-1-1.4-.3-.5-.5-1.1-.8-1.8-2 2.3-4.4 3.5-7.4 3.5-2.1 0-3.8-.6-5-1.8-1.2-1.2-1.8-2.8-1.8-4.8 0-2.1.7-3.8 2.2-5.1 1.5-1.3 3.5-1.9 6-1.9.8 0 1.7.1 2.6.2.9.1 1.9.3 2.9.6v-1.8c0-1.9-.4-3.2-1.2-4-.8-.8-2.1-1.1-4-1.1-.9 0-1.8.1-2.7.3-.9.2-1.8.5-2.7.9-.4.2-.7.3-.9.3-.3 0-.5-.2-.5-.7V6.6c0-.4.1-.6.2-.8.1-.2.4-.3.8-.5.9-.5 2-.8 3.2-1.1 1.2-.3 2.5-.4 3.9-.4 3 0 5.1.7 6.5 2 1.3 1.3 2 3.3 2 6v7.9zm-10.2 3.8c.8 0 1.6-.1 2.5-.4.9-.3 1.7-.8 2.3-1.5.4-.5.7-1 .8-1.6.1-.6.2-1.3.2-2.1v-1c-.7-.2-1.5-.3-2.2-.4-.8-.1-1.5-.1-2.2-.1-1.6 0-2.7.3-3.5 1-.8.6-1.1 1.5-1.1 2.7 0 1.1.3 1.9.8 2.5.6.5 1.4.9 2.4.9zm18.9 2.5c-.4 0-.7-.1-.9-.2-.2-.1-.4-.5-.5-.9L25.6 4.4c-.1-.5-.2-.8-.2-1 0-.4.2-.6.6-.6h2.5c.5 0 .8.1.9.2.2.1.3.5.5.9l3.8 15 3.5-15c.1-.5.3-.8.5-.9.2-.1.5-.2 1-.2h2c.5 0 .8.1 1 .2.2.1.4.5.5.9l3.5 15.2 3.9-15.2c.1-.5.3-.8.5-.9.2-.1.5-.2.9-.2h2.4c.4 0 .6.2.6.6 0 .1 0 .3-.1.5l-.1.5-5.5 20.5c-.1.5-.3.8-.5.9-.2.1-.5.2-.9.2h-2.2c-.5 0-.8-.1-1-.2-.2-.1-.4-.5-.5-1L40 11.6l-3.5 14.2c-.1.5-.3.8-.5 1-.2.1-.5.2-1 .2h-2.2c-.4 0-.7-.1-.9-.2-.2-.1-.4-.5-.5-.9l-.8-3.8zm29.4.6c-1.3 0-2.7-.2-4-.5-1.3-.3-2.3-.7-3-1.1-.4-.2-.7-.5-.8-.8-.1-.2-.1-.5-.1-.7v-1.4c0-.5.2-.7.5-.7.1 0 .3 0 .4.1l.6.3c.8.4 1.7.7 2.7.9 1 .2 1.9.3 2.9.3 1.5 0 2.7-.3 3.5-.8.8-.5 1.2-1.3 1.2-2.2 0-.6-.2-1.2-.6-1.6-.4-.4-1.2-.8-2.3-1.2l-3.3-1c-1.7-.5-2.9-1.3-3.7-2.3-.8-1-1.2-2.1-1.2-3.3 0-1 .2-1.8.6-2.6.4-.8 1-1.4 1.7-1.9.7-.5 1.5-.9 2.4-1.2.9-.3 1.9-.4 2.9-.4.5 0 1 0 1.5.1.5.1 1 .2 1.5.3.5.1.9.2 1.3.4.4.1.7.3.9.4.3.2.5.4.6.6.1.2.2.4.2.7v1.3c0 .5-.2.7-.5.7-.2 0-.5-.1-.9-.3-1.2-.5-2.5-.8-4-.8-1.4 0-2.4.2-3.2.7-.8.5-1.1 1.2-1.1 2.2 0 .6.2 1.2.7 1.6.5.4 1.3.9 2.6 1.3l3.2 1c1.6.5 2.8 1.2 3.5 2.2.7.9 1.1 2 1.1 3.2 0 1-.2 1.9-.6 2.7-.4.8-1 1.5-1.7 2-.7.6-1.6 1-2.6 1.3-1.1.3-2.2.5-3.4.5z" fill="#FF9900"/>
  <path d="M58.4 36.2c-7 5.2-17.2 7.9-26 7.9-12.3 0-23.4-4.5-31.8-12-.7-.6-.1-1.4.7-1 9 5.3 20.1 8.5 31.6 8.5 7.7 0 16.2-1.6 24-4.9 1.2-.5 2.1.8.9 1.5h-.4z" fill="#FF9900"/>
  <path d="M61.3 32.9c-.9-1.2-6.1-.6-8.5-.3-.7.1-.8-.5-.2-.9 4.1-2.9 10.9-2.1 11.7-1.1.8 1-.2 7.8-4.1 11-.6.5-1.1.2-.9-.4.9-2.2 2.9-7.1 2-8.3z" fill="#FF9900"/>
</svg>""",

    "azure": """<svg viewBox="0 0 96 96" width="40" height="40" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="az1" x1="0.677" y1="0.271" x2="0.46" y2="0.84" gradientUnits="objectBoundingBox">
      <stop offset="0" stop-color="#114a8b"/>
      <stop offset="1" stop-color="#0669bc"/>
    </linearGradient>
    <linearGradient id="az2" x1="0.372" y1="0.307" x2="0.596" y2="0.777" gradientUnits="objectBoundingBox">
      <stop offset="0" stop-opacity=".3"/>
      <stop offset="0.071" stop-opacity=".2"/>
      <stop offset="0.321" stop-opacity=".1"/>
      <stop offset="0.623" stop-opacity=".05"/>
      <stop offset="1" stop-opacity="0"/>
    </linearGradient>
    <linearGradient id="az3" x1="0.197" y1="0.293" x2="0.816" y2="0.745" gradientUnits="objectBoundingBox">
      <stop offset="0" stop-color="#3ccbf4"/>
      <stop offset="1" stop-color="#2892df"/>
    </linearGradient>
  </defs>
  <path d="M33.338 6.544h26.038L33.476 89.456a4.152 4.152 0 01-3.933 2.8H8.149a4.145 4.145 0 01-3.928-5.47L29.405 9.344a4.152 4.152 0 013.933-2.8z" fill="url(#az1)"/>
  <path d="M71.175 60.261H29.972a1.911 1.911 0 00-1.305 3.309l26.561 24.764a4.171 4.171 0 002.846 1.122h23.447z" fill="url(#az2)"/>
  <path d="M33.338 6.544a4.118 4.118 0 00-3.943 2.879L4.252 86.744a4.14 4.14 0 003.908 5.512h20.787a4.443 4.443 0 003.41-2.9l5.014-14.777 17.91 16.705a4.237 4.237 0 002.666.972H81.24L71.024 60.261l-29.781.007L56.769 6.544z" fill="url(#az3)"/>
  <path d="M66.595 9.344a4.145 4.145 0 00-3.928-2.8H33.648a4.146 4.146 0 013.928 2.8l25.184 77.442a4.146 4.146 0 01-3.928 5.47h29.019a4.146 4.146 0 003.928-5.47z" fill="#1389fd"/>
</svg>""",

    "gcp": """<svg viewBox="0 0 48 48" width="40" height="40" xmlns="http://www.w3.org/2000/svg">
  <path d="M30.2 14.1l3.3-3.3.2-1.4C27.9 4 19.6 2.1 12.4 5.7 5.2 9.3 1 16.6 1.5 24.3l1.2-.2 6.6-1.1.5-.5c.3-3.5 2.3-6.7 5.4-8.6 3.1-1.9 6.9-2.2 10.3-.9l4.7-4.7v5.8z" fill="#EA4335"/>
  <path d="M46.5 24.3c-.6-5.1-3-9.8-6.8-13.3l-7 7c2.9 2.4 4.6 5.9 4.6 9.7v1.2c3.3 0 6 2.7 6 6s-2.7 6-6 6H24l-1.2 1.2v7.2l1.2 1.2h13.3c8.6.1 15.7-6.8 15.7-15.4.1-5.1-2.4-9.9-6.5-12.8z" fill="#4285F4"/>
  <path d="M10.7 48h13.3v-9.6H10.7c-.9 0-1.8-.2-2.6-.6l-1.8.6-6.6 1.1-1.2 1.2c2.4 4.6 7.2 7.3 12.2 7.3z" fill="#34A853"/>
  <path d="M10.7 17.6C2.1 17.6-2.6 27.9 2.8 34.5l7-7c-1.5-1.7-1.5-4.2 0-5.9l-7-7c-1.5 1.7-2.3 3.9-2.3 6.2.1 5.1 4.2 9.2 9.3 9.2 2.3 0 4.5-.8 6.2-2.3l-7-7c1.7-1.5 4.2-1.5 5.9 0l7-7c-2.7-2.5-6.2-3.9-9.9-3.9z" fill="#FBBC05"/>
</svg>""",
}


# ── PDF Icon rendering (draw SVG shapes natively via fpdf2) ───────────────────
# Each function receives the pdf object and top-left (x, y) + size in mm.

def draw_aws_icon(pdf, x: float, y: float, size: float = 12) -> None:
    """Draw the AWS smile-arrow logo using native fpdf2 shapes."""
    s = size / 12  # scale factor

    # Orange colour
    pdf.set_fill_color(255, 153, 0)
    pdf.set_draw_color(255, 153, 0)

    # Top "AWS" text block — simplified as a filled rounded rect
    pdf.set_font("Helvetica", "B", size * 0.75)
    pdf.set_text_color(255, 153, 0)
    pdf.set_xy(x, y)
    pdf.cell(size * 1.4, size * 0.55, "aws", align="C")

    # Smile arc — approximate with a thin rectangle
    pdf.set_fill_color(255, 153, 0)
    arc_y = y + size * 0.65
    arc_w = size * 1.4
    arc_h = size * 0.12
    pdf.rect(x, arc_y, arc_w, arc_h, "F")

    # Left arrow tip
    pdf.rect(x, arc_y, arc_w * 0.12, arc_h * 2, "F")
    # Right arrow tip
    pdf.rect(x + arc_w - arc_w * 0.12, arc_y - arc_h, arc_w * 0.12, arc_h * 2, "F")


def draw_azure_icon(pdf, x: float, y: float, size: float = 12) -> None:
    """Draw a simplified Azure 'A' chevron logo using rect blocks."""
    # Left pillar (dark blue)
    pdf.set_fill_color(17, 74, 139)
    pdf.rect(x, y + size * 0.2, size * 0.35, size * 0.8, "F")

    # Right pillar (light blue)
    pdf.set_fill_color(19, 137, 253)
    pdf.rect(x + size * 0.65, y + size * 0.2, size * 0.35, size * 0.8, "F")

    # Top bridge connecting both (cyan)
    pdf.set_fill_color(44, 146, 223)
    pdf.rect(x + size * 0.25, y, size * 0.5, size * 0.35, "F")


def draw_gcp_icon(pdf, x: float, y: float, size: float = 12) -> None:
    """Draw a simplified GCP 4-colour cloud icon as coloured blocks."""
    half = size / 2
    q    = size / 4

    # Red (top-left)
    pdf.set_fill_color(234, 67, 53)
    pdf.rect(x,        y,        half, half, "F")
    # Blue (top-right)
    pdf.set_fill_color(66, 133, 244)
    pdf.rect(x + half, y,        half, half, "F")
    # Yellow (bottom-left)
    pdf.set_fill_color(251, 188, 5)
    pdf.rect(x,        y + half, half, half, "F")
    # Green (bottom-right)
    pdf.set_fill_color(52, 168, 83)
    pdf.rect(x + half, y + half, half, half, "F")

    # White centre square to create the "G" cutout feel
    pdf.set_fill_color(8, 11, 16)   # match BG
    pdf.rect(x + q, y + q, half, half, "F")


# ── Dispatch helper ───────────────────────────────────────────────────────────

PDF_ICON_RENDERERS = {
    "aws":   draw_aws_icon,
    "azure": draw_azure_icon,
    "gcp":   draw_gcp_icon,
}


def draw_cloud_icon_pdf(pdf, cloud: str, x: float, y: float, size: float = 12) -> None:
    """Draw the icon for `cloud` onto `pdf` at position (x, y)."""
    renderer = PDF_ICON_RENDERERS.get(cloud.lower())
    if renderer:
        renderer(pdf, x, y, size)


def get_svg_icon(cloud: str) -> str:
    """Return the SVG string for use in HTML."""
    return SVG_ICONS.get(cloud.lower(), "")
