import streamlit as st
import streamlit_shadcn_ui as ui

from dashboard.pdf import generate_pdf_report
from dashboard.visuals import build_findings_rows_html, build_severity_pie

SEV_ORDER = ["Critical", "High", "Medium", "Low"]

def page_dashboard():
    report   = st.session_state.results
    meta     = report["scan_metadata"]
    summary  = report["summary"]
    findings = report["findings"]

    sc       = summary["severity_counts"]
    scope    = meta["cloud_scope"].upper()
    dur_raw  = meta.get("scan_duration_seconds", 0)
    dur_str  = "< 1s" if dur_raw == 0 else (f"{dur_raw:.2f}s" if dur_raw < 1 else f"{dur_raw:.1f}s")
    ts       = meta["scan_started_at"][:19].replace("T", " ") + " UTC"
    account  = meta.get("target_account", "N/A")
    passed   = sum(1 for f in findings if f.get("status") == "PASS")
    failed   = sum(1 for f in findings if f.get("status") == "FAIL")

    # ── Top bar ───────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="nb-topbar">
      <div class="nb-topbar-left">
        <span class="nb-topbar-logo">🔭 NEBULOUPE</span>
        <span class="nb-topbar-sep">/</span>
        <span class="nb-topbar-page">Security Findings</span>
      </div>
      <div class="nb-topbar-right">
        <span class="nb-topbar-chip">{scope}</span>
        <span class="nb-topbar-account">{account}</span>
        <span class="nb-topbar-ts">{ts}</span>
        <span class="nb-topbar-dur">⏱ {dur_str}</span>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    # ── Stat cards ────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="nb-stat-grid">
      <div class="nb-stat-card c-total">
        <div class="nb-stat-label">Total Findings</div>
        <div class="nb-stat-num c-total">{summary["total_findings"]}</div>
        <div class="nb-stat-sub">Risk score: {summary["severity_score_total"]}</div>
      </div>
      <div class="nb-stat-card c-crit">
        <div class="nb-stat-label">Critical</div>
        <div class="nb-stat-num c-crit">{sc["Critical"]}</div>
        <div class="nb-stat-sub">Immediate action</div>
      </div>
      <div class="nb-stat-card c-high">
        <div class="nb-stat-label">High</div>
        <div class="nb-stat-num c-high">{sc["High"]}</div>
        <div class="nb-stat-sub">Urgent remediation</div>
      </div>
      <div class="nb-stat-card c-med">
        <div class="nb-stat-label">Medium</div>
        <div class="nb-stat-num c-med">{sc["Medium"]}</div>
        <div class="nb-stat-sub">Schedule fix</div>
      </div>
      <div class="nb-stat-card c-low">
        <div class="nb-stat-label">Low</div>
        <div class="nb-stat-num c-low">{sc["Low"]}</div>
        <div class="nb-stat-sub">Monitor &amp; review</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    # ── Chart + filters ───────────────────────────────────────────────────────
    chart_col, filter_col = st.columns([1, 2], gap="large")

    with chart_col:
        st.markdown('<div class="nb-sec-hdr">Severity Breakdown</div>', unsafe_allow_html=True)
        fig = build_severity_pie(
            total_findings=summary["total_findings"],
            severity_counts=sc,
            severity_order=SEV_ORDER,
        )
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    with filter_col:
        st.markdown('<div class="nb-sec-hdr">Filters</div>', unsafe_allow_html=True)
        fc1, fc2 = st.columns(2)
        with fc1:
            sev_opts   = SEV_ORDER
            sev_filter = st.multiselect("Severity", sev_opts, default=sev_opts, key="sev_filter")
        with fc2:
            cat_opts   = sorted({f.get("category", "Uncategorized") for f in findings})
            cat_filter = st.multiselect("Category", cat_opts, default=cat_opts, key="cat_filter")

        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

        # Pass / Fail summary
        st.markdown(f"""
        <div class="nb-pf-row">
          <div class="nb-pf-box fail">
            <span class="nb-pf-dot"></span>
            <div><div class="nb-pf-num">{failed}</div><div class="nb-pf-lbl">Failed</div></div>
          </div>
          <div class="nb-pf-box pass">
            <span class="nb-pf-dot"></span>
            <div><div class="nb-pf-num">{passed}</div><div class="nb-pf-lbl">Passed</div></div>
          </div>
          <div class="nb-pf-box total">
            <span class="nb-pf-dot"></span>
            <div><div class="nb-pf-num">{len(findings)}</div><div class="nb-pf-lbl">Total Checks</div></div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    # ── Findings table ────────────────────────────────────────────────────────
    filtered = [
        f for f in findings
        if f.get("severity", "Unknown") in sev_filter
        and f.get("category", "Uncategorized") in cat_filter
    ]
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "Unknown"), 99))

    st.markdown(f"""
    <div class="nb-sec-hdr" style="margin-bottom:12px;">
      Findings
      <span class="nb-count-chip">{len(filtered)} of {len(findings)}</span>
    </div>
    """, unsafe_allow_html=True)

    rows_html = build_findings_rows_html(filtered)
    st.markdown(f"""
    <div class="nb-tbl-wrap">
      <table class="nb-table">
        <thead><tr>
          <th>Severity</th><th>Cloud</th><th>Rule ID</th><th>Check</th>
          <th>Resource ID</th><th>Region</th><th>Category</th>
          <th>Description</th><th>Status</th>
        </tr></thead>
        <tbody>
          {rows_html if rows_html else
           '<tr><td colspan="9" class="nb-tbl-empty">No findings match the current filters.</td></tr>'}
        </tbody>
      </table>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # ── Action bar ────────────────────────────────────────────────────────────
    _, a1, a2, _ = st.columns([3, 1, 1, 3])
    with a1:
        pdf_bytes = generate_pdf_report(report)
        if pdf_bytes:
            st.download_button(
                label="⬇  Export PDF",
                data=pdf_bytes,
                file_name=f"nebuloupe-report-{meta.get('scan_id','scan')}.pdf",
                mime="application/pdf",
              width="stretch",
            )
    with a2:
          if st.button("← New Scan", key="new_scan", width="stretch"):
            st.session_state.page     = "landing"
            st.session_state.results  = None
            st.session_state.selected_clouds = []
            st.session_state.scanning = False
            st.rerun()

    st.markdown("""
<div class="nb-footer">
  <div class="nb-footer-brand">&#128301; NEBULOUPE</div>
  <div class="nb-footer-links">
    <span class="nb-footer-link">Documentation</span>
    <span class="nb-footer-sep">&#183;</span>
    <span class="nb-footer-link">GitHub</span>
    <span class="nb-footer-sep">&#183;</span>
    <span class="nb-footer-link">Report Issue</span>
    <span class="nb-footer-sep">&#183;</span>
    <span class="nb-footer-link">Changelog</span>
  </div>
  <div class="nb-footer-copy">Cloud Misconfiguration Security Scanner &nbsp;&middot;&nbsp; v1.0 &nbsp;&middot;&nbsp; Open Source</div>
</div>
""", unsafe_allow_html=True)
