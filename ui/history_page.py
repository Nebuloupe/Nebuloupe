import streamlit as st

from ui.history_store import load_scan_history


def page_history():
    st.markdown(
        """
<div class=\"nb-topbar\">
  <div class=\"nb-topbar-left\">
    <span class=\"nb-topbar-logo\">🔭 NEBULOUPE</span>
    <span class=\"nb-topbar-sep\">/</span>
    <span class=\"nb-topbar-page\">Scan History</span>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    back_col, _ = st.columns([1, 5])
    with back_col:
        if st.button("← Back", key="history_back", width="stretch"):
            st.session_state.page = "landing"
            st.rerun()

    history = load_scan_history()
    if not history:
        st.info("No previous scans found yet. Run a scan to populate history.")
        return

    st.markdown(
        """
<style>
div[class*="st-key-hist_row_"] button {
    width: 100% !important;
    display: flex !important;
    justify-content: flex-start !important;
    align-items: flex-start !important;
    padding: 14px 18px !important;
    border-radius: 14px !important;
    border: 1px solid #1e293b !important;
    background: #0a0f1e !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 12px !important;
    font-weight: 500 !important;
    letter-spacing: 0 !important;
    text-transform: none !important;
    line-height: 1.6 !important;
    text-align: left !important;
    text-indent: 0 !important;
    white-space: pre-line !important;
    box-shadow: none !important;
}
div[class*="st-key-hist_row_"] button::before,
div[class*="st-key-hist_row_"] button::after {
    content: none !important;
    display: none !important;
}
div[class*="st-key-hist_row_"] button:hover {
    transform: none !important;
    border-color: #334155 !important;
    background: #0b1220 !important;
    box-shadow: none !important;
}
div[class*="st-key-hist_row_"] button > div {
    width: 100% !important;
    display: block !important;
    text-align: left !important;
}
div[class*="st-key-hist_row_"] button p {
    margin: 0 !important;
    text-align: left !important;
}
</style>
""",
        unsafe_allow_html=True,
    )

    st.markdown('<div class="nb-sec-hdr">Previous Scans</div>', unsafe_allow_html=True)

    for i, item in enumerate(history):
        cloud = str(item.get("cloud_scope", "unknown")).upper()
        findings = item.get("total_findings", 0)
        score = item.get("severity_score_total", 0)
        status = str(item.get("status", "unknown")).upper()
        started = item.get("scan_started_at", "")

        row_label = (
            f"{cloud} • {status}\n"
            f"Findings: {findings} • Risk Score: {score}\n"
            f"Started: {started}"
        )
        if st.button(row_label, key=f"hist_row_{i}", width="stretch"):
            st.session_state.results = item.get("report")
            st.session_state.page = "dashboard"
            st.rerun()

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
