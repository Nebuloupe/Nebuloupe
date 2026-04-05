import streamlit as st

from dashboard.pdf import generate_pdf_report
from dashboard.visuals import build_findings_rows_html, build_severity_pie

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def page_dashboard():
    report = st.session_state.results
    meta = report["scan_metadata"]
    summary = report["summary"]
    findings = report["findings"]

    severity_counts = summary["severity_counts"]
    scope_str = meta["cloud_scope"].upper()
    dur_raw = meta.get("scan_duration_seconds", 0)
    if dur_raw == 0:
        dur_str = "< 1s"
    elif dur_raw < 1:
        dur_str = f"{dur_raw:.2f}s"
    else:
        dur_str = f"{dur_raw:.1f}s"
    ts = meta["scan_started_at"][:19].replace("T", " ") + " UTC"

    col_left, col_right = st.columns([3, 1])
    with col_left:
        st.markdown(
            """
        <div style="display:flex;align-items:center;gap:12px;padding:20px 0 0 8px;">
          <span style="font-size:28px;filter:drop-shadow(0 0 10px rgba(0,220,160,0.6))">🔭</span>
          <span class="nb-dash-logo">NEBULOUPE</span>
          <span style="font-size:11px;color:#444c56;letter-spacing:2px;text-transform:uppercase;margin-left:8px;">
            / FINDINGS DASHBOARD
          </span>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col_right:
        st.markdown(
            f"""
        <div class="nb-dash-meta" style="padding:20px 8px 0 0;">
          <div class="nb-meta-row">
            <span class="nb-meta-label">Scope</span>
            <span class="nb-meta-sep">·</span>
            <span class="nb-meta-value">{scope_str}</span>
            <span class="nb-meta-sep" style="margin:0 4px;">|</span>
            <span class="nb-meta-label">Duration</span>
            <span class="nb-meta-sep">·</span>
            <span class="nb-meta-value">{dur_str}</span>
          </div>
          <div class="nb-meta-ts">{ts}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown('<hr style="border:none;border-top:1px solid #21262d;margin:12px 0 0;">', unsafe_allow_html=True)
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    s1, s2, s3, s4, s5 = st.columns(5)

    def stat_card(col, css_cls, label, value, sub=""):
        with col:
            st.markdown(
                f"""
            <div class="nb-stat-card {css_cls}">
              <div class="nb-stat-label">{label}</div>
              <div class="nb-stat-value {css_cls}">{value}</div>
              <div class="nb-stat-sub">{sub}</div>
            </div>""",
                unsafe_allow_html=True,
            )

    stat_card(s1, "total", "Total Findings", summary["total_findings"], f"Score: {summary['severity_score_total']}")
    stat_card(s2, "Critical", "Critical", severity_counts["Critical"], "Score ×10")
    stat_card(s3, "High", "High", severity_counts["High"], "Score ×7")
    stat_card(s4, "Medium", "Medium", severity_counts["Medium"], "Score ×4")
    stat_card(s5, "Low", "Low", severity_counts["Low"], "Score ×1")

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
    chart_col, filter_col = st.columns([1, 1.5], gap="large")
    with chart_col:
        st.markdown('<div class="nb-findings-title" style="margin-bottom:-10px;">Severity Breakdown</div>', unsafe_allow_html=True)
        fig = build_severity_pie(
            total_findings=summary["total_findings"],
            severity_counts=severity_counts,
            severity_order=SEV_ORDER,
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with filter_col:
        st.markdown('<div class="nb-findings-title" style="margin-bottom:-10px;">Filter & Scan</div>', unsafe_allow_html=True)
        f1, f2, f3, rescan_col = st.columns([1.5, 1.5, 1.5, 1.5])
        with f1:
            sev_opts = SEV_ORDER + (["Unknown"] if any("severity" not in f for f in findings) else [])
            sev_filter = st.multiselect("Severity", sev_opts, default=sev_opts, key="sev_filter", label_visibility="visible")
        with f2:
            cloud_opts = sorted({f.get("cloud_provider", "unknown") for f in findings})
            cloud_filter = st.multiselect("Cloud", cloud_opts, default=cloud_opts, key="cloud_filter")
        with f3:
            cat_opts = sorted({f.get("category", "Uncategorized") for f in findings})
            cat_filter = st.multiselect("Category", cat_opts, default=cat_opts, key="cat_filter")
        with rescan_col:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            st.markdown('<div class="nb-rescan-btn">', unsafe_allow_html=True)
            if st.button("← New Scan", key="new_scan"):
                st.session_state.page = "landing"
                st.session_state.results = None
                st.session_state.selected_clouds = []
                st.session_state.scanning = False
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    filtered = [
        f
        for f in findings
        if f.get("severity", "Unknown") in sev_filter
        and f.get("cloud_provider", "unknown") in cloud_filter
        and f.get("category", "Uncategorized") in cat_filter
    ]
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "Unknown"), 99))

    st.markdown(
        f"""
    <div class="nb-findings-title" style="margin-top:8px;">
      Findings &nbsp;<span style="font-size:12px;color:#444c56;font-family:'JetBrains Mono'">
      {len(filtered)} of {len(findings)} shown
      </span>
    </div>""",
        unsafe_allow_html=True,
    )

    rows_html = build_findings_rows_html(filtered)
    st.markdown(
        f"""
<div style="background:#0d1117;border:1px solid #21262d;border-radius:12px;overflow:hidden;">
  <table class="nb-table">
    <thead>
      <tr>
        <th>Severity</th><th>Cloud</th><th>Rule ID</th><th>Check</th>
        <th>Resource Type</th><th>Resource ID</th><th>Region</th>
        <th>Description</th><th>Status</th>
      </tr>
    </thead>
    <tbody>
      {rows_html if rows_html else '<tr><td colspan="9" style="text-align:center;color:#444c56;padding:40px;">No findings match the current filters.</td></tr>'}
    </tbody>
  </table>
</div>
""",
        unsafe_allow_html=True,
    )

    pdf_bytes = generate_pdf_report(report)
    if pdf_bytes:
        st.download_button(
            label="Download PDF Report",
            data=pdf_bytes,
            file_name=f"nebuloupe-report-{meta.get('scan_id', 'scan')}.pdf",
            mime="application/pdf",
        )

    st.markdown(
        """
    <div style="text-align:center;padding:32px 0 16px;color:#21262d;font-size:10px;letter-spacing:2px;text-transform:uppercase;">
      Nebuloupe · Multi-Cloud Security Scanner · Demo Mode
    </div>
    """,
        unsafe_allow_html=True,
    )
