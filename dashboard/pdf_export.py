# Re-export from the new pdf package for backwards compatibility.
from dashboard.pdf import generate_pdf_report

__all__ = ["generate_pdf_report"]
