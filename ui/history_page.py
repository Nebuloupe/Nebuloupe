import streamlit as st
import streamlit_shadcn_ui as ui

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

    st.markdown('<div class="nb-sec-hdr">Previous Scans</div>', unsafe_allow_html=True)

    for i, item in enumerate(history):
        cloud = str(item.get("cloud_scope", "unknown")).upper()
        findings = item.get("total_findings", 0)
        score = item.get("severity_score_total", 0)
        status = str(item.get("status", "unknown")).upper()
        started = item.get("scan_started_at", "")

        info_col, btn_col = st.columns([5, 1])
        with info_col:
            st.markdown(
                f"""
<div class=\"nb-stat-card\" style=\"margin-bottom:10px;\">
  <div class=\"nb-stat-label\">{cloud} • {status}</div>
  <div style=\"font-size:13px;color:#e2e8f0;\">Findings: {findings} • Risk Score: {score}</div>
  <div style=\"font-size:11px;color:#94a3b8;margin-top:4px;\">Started: {started}</div>
</div>
""",
                unsafe_allow_html=True,
            )
        with btn_col:
            if ui.button(text="Open", key=f"open_hist_{i}"):
                st.session_state.results = item.get("report")
                st.session_state.page = "dashboard"
                st.rerun()
