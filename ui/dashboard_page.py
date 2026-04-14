import streamlit as st
from collections import Counter

from ui.pdf import generate_pdf_report
from ui.visuals import build_findings_rows_html

SEV_ORDER = ["Critical", "High", "Medium", "Low"]


def page_dashboard():
    report = st.session_state.results
    meta = report["scan_metadata"]
    summary = report["summary"]
    findings = report["findings"]

    sc = summary["severity_counts"]
    scope = meta["cloud_scope"].upper()
    dur_raw = meta.get("scan_duration_seconds", 0)
    dur_str = "< 1s" if dur_raw == 0 else (f"{dur_raw:.2f}s" if dur_raw < 1 else f"{dur_raw:.1f}s")
    ts = meta["scan_started_at"][:19].replace("T", " ") + " UTC"
    account = meta.get("target_account", "N/A")
    passed = sum(1 for f in findings if f.get("status") == "PASS")
    failed = sum(1 for f in findings if f.get("status") == "FAIL")
    fail_total = max(failed, 1)

    severity_weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    score_total = int(summary.get("severity_score_total", 0))
    # Max weighted score should respect each finding's own severity, not assume all are Critical.
    score_max = sum(severity_weights.get(f.get("severity", "Low"), 0) for f in findings)
    score_max = max(score_max, 1)
    score_pct = int(round((score_total / score_max) * 100)) if score_max else 0

    def _watch_service_name(finding):
        category = str(finding.get("category", "")).strip()
        if category:
            return category
        rtype = str(finding.get("resource_type", "")).strip()
        if "/" in rtype:
            return rtype.split("/")[0].replace("Microsoft.", "")
        if rtype:
            return rtype.split("_")[0].replace("aws", "AWS")
        return "unknown"

    service_counter = Counter(_watch_service_name(f) for f in findings if f.get("status") == "FAIL")
    top_services = service_counter.most_common(5)

    st.markdown(
        f"""
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
""",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)

    st.markdown(
        """
<style>
.nb-ana-card{background:linear-gradient(180deg,#0a0f1e,#070b16);border:1px solid #182235;border-radius:16px;padding:14px 14px 6px;display:flex;flex-direction:column;overflow:hidden;}
.nb-ana-title{font-size:11px;font-weight:700;letter-spacing:1.2px;text-transform:uppercase;color:#9fb0c8;margin-bottom:12px;}
.nb-score-number{font-family:'Space Grotesk',sans-serif;font-size:46px;font-weight:800;color:#f8fafc;line-height:1;}
.nb-score-sub{font-size:12px;color:#94a3b8;margin-top:4px;}
.nb-meter{height:12px;border-radius:999px;background:#111827;overflow:hidden;border:1px solid #1f2937;margin-top:14px;}
.nb-meter-fill{height:100%;background:linear-gradient(90deg,#22c55e,#f59e0b,#ef4444);}
.nb-split{height:16px;border-radius:999px;background:#0f172a;overflow:hidden;border:1px solid #1f2937;display:flex;}
.nb-split-fail{background:#ff2d6f;}
.nb-split-pass{background:#12d984;}
.nb-mini-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px;}
.nb-mini{background:#0b1220;border:1px solid #1e293b;border-radius:10px;padding:7px 8px 5px;}
.nb-mini-v{font-family:'JetBrains Mono',monospace;font-size:18px;font-weight:700;}
.nb-mini-l{font-size:10px;color:#94a3b8;letter-spacing:0.4px;text-transform:uppercase;}
.nb-pie-wrap{display:flex;justify-content:center;align-items:center;padding:2px 0 0;}
.nb-pie{width:142px;height:142px;border-radius:50%;position:relative;background:conic-gradient(#ff2d6f 0 var(--fail-end), #12d984 var(--fail-end) 100%);}
.nb-pie::after{content:'';position:absolute;inset:21px;border-radius:50%;background:#090f1b;box-shadow:inset 0 0 0 1px #182235;}
.nb-pie-center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:2;}
.nb-pie-total{font-family:'Space Grotesk',sans-serif;font-size:27px;font-weight:800;color:#f8fafc;line-height:1;}
.nb-pie-sub{font-size:10px;color:#94a3b8;margin-top:2px;}
.nb-check-layout{display:grid;grid-template-columns:152px 1fr;gap:8px;align-items:center;}
.nb-check-stats{display:grid;grid-template-columns:1fr;gap:7px;}
.nb-sv-row{display:grid;grid-template-columns:52px 1fr auto;column-gap:0;align-items:center;margin-bottom:12px;}
.nb-sv-label{color:#cbd5e1;font-size:13px;padding-right:6px;}
.nb-sv-track{height:10px;background:#111827;border-radius:4px;overflow:hidden;}
.nb-sv-fill{height:100%;border-radius:4px;}
.nb-sv-val{text-align:right;color:#cbd5e1;font-size:13px;padding-left:4px;white-space:nowrap;}
.nb-watch-row{display:grid;grid-template-columns:58px 1fr auto;column-gap:0;align-items:center;margin-bottom:12px;}
.nb-watch-label{font-size:13px;color:#e2e8f0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.nb-watch-track{height:10px;background:#111827;border-radius:4px;overflow:hidden;}
.nb-watch-fill{height:100%;background:linear-gradient(90deg,#f97316,#fb923c);border-radius:4px;}
.nb-watch-val{text-align:right;color:#f97316;font-family:'JetBrains Mono',monospace;font-weight:700;font-size:13px;padding-left:4px;white-space:nowrap;}
.nb-analytics-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;align-items:stretch;}
.nb-analytics-grid .nb-ana-card{height:100%;}
.nb-sev-mini-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:10px;}
.nb-sev-mini{background:#0a0f1e;border:1px solid #182235;border-radius:12px;padding:10px 12px;}
.nb-sev-mini-top{font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:#94a3b8;}
.nb-sev-mini-val{font-family:'Space Grotesk',sans-serif;font-size:36px;font-weight:900;line-height:1.02;margin-top:6px;}
.nb-sev-mini-sub{font-size:12px;color:#a3b2c7;margin-top:3px;font-weight:600;}
.nb-sev-mini.crit{border-color:rgba(239,68,68,0.55);box-shadow:inset 0 0 0 1px rgba(239,68,68,0.15);}
.nb-sev-mini.high{border-color:rgba(249,115,22,0.55);box-shadow:inset 0 0 0 1px rgba(249,115,22,0.15);}
.nb-sev-mini.med{border-color:rgba(234,179,8,0.55);box-shadow:inset 0 0 0 1px rgba(234,179,8,0.15);}
.nb-sev-mini.low{border-color:rgba(34,197,94,0.55);box-shadow:inset 0 0 0 1px rgba(34,197,94,0.15);}
.nb-sev-mini.crit .nb-sev-mini-val{color:#ef4444;}
.nb-sev-mini.high .nb-sev-mini-val{color:#f97316;}
.nb-sev-mini.med .nb-sev-mini-val{color:#eab308;}
.nb-sev-mini.low .nb-sev-mini-val{color:#22c55e;}
</style>
""",
        unsafe_allow_html=True,
    )

    fail_pct = int(round((failed / max(len(findings), 1)) * 100))
    pass_pct = 100 - fail_pct
    total_checks = len(findings)

    severity_card_html = f"""
<div class="nb-ana-card">
  <div class="nb-ana-title">Severity Score</div>
  <div class="nb-score-number">{score_total:,}</div>
  <div class="nb-score-sub">of {score_max:,} max weighted score</div>
  <div class="nb-meter"><div class="nb-meter-fill" style="width:{score_pct}%;"></div></div>
  <div style="margin-top:10px;color:#cbd5e1;font-size:13px;">Score Utilization: <b>{score_pct}%</b></div>
  <div style="margin-top:6px;color:#94a3b8;font-size:12px;line-height:1.5;">Weighted by severity: Critical 10, High 7, Medium 4, Low 1.</div>
</div>
"""

    check_card_html = f"""
<div class="nb-ana-card">
  <div class="nb-ana-title">Check Findings</div>
  <div class="nb-check-layout">
    <div class="nb-pie-wrap">
      <div class="nb-pie" style="--fail-end:{fail_pct}%;">
        <div class="nb-pie-center">
          <div class="nb-pie-total">{total_checks:,}</div>
          <div class="nb-pie-sub">Total Findings</div>
        </div>
      </div>
    </div>
    <div class="nb-check-stats">
      <div class="nb-mini"><div class="nb-mini-v" style="color:#ff2d6f;">{failed:,}</div><div class="nb-mini-l">Fail Findings ({fail_pct}%)</div></div>
      <div class="nb-mini"><div class="nb-mini-v" style="color:#12d984;">{passed:,}</div><div class="nb-mini-l">Pass Findings ({pass_pct}%)</div></div>
    </div>
  </div>
</div>
"""

    if top_services:
        rows = []
        for service, count in top_services:
            width_pct = 0 if failed == 0 else int(round((count / fail_total) * 100))
            rows.append(
                f'<div class="nb-watch-row">'
                f'<div class="nb-watch-label">{service}</div>'
                f'<div class="nb-watch-track"><div class="nb-watch-fill" style="width:{width_pct}%;"></div></div>'
                f'<div class="nb-watch-val">{width_pct}% | {count:,}</div></div>'
            )
        watch_content = "".join(rows)
    else:
        watch_content = '<div style="color:#94a3b8;font-size:13px;">No failed services to show.</div>'

    watch_card_html = '<div class="nb-ana-card"><div class="nb-ana-title">Service Watchlist</div>' + watch_content + '</div>'

    st.markdown(
        '<div class="nb-analytics-grid">' + severity_card_html + check_card_html + watch_card_html + '</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="nb-sec-hdr" style="margin-top:14px;">Risk Severity</div>
<div class="nb-sev-mini-grid">
  <div class="nb-sev-mini crit">
    <div class="nb-sev-mini-top">Critical</div>
    <div class="nb-sev-mini-val">{int(sc.get('Critical', 0)):,}</div>
    <div class="nb-sev-mini-sub">{(0 if failed == 0 else round((int(sc.get('Critical', 0)) / failed) * 100))}% of fails</div>
  </div>
  <div class="nb-sev-mini high">
    <div class="nb-sev-mini-top">High</div>
    <div class="nb-sev-mini-val">{int(sc.get('High', 0)):,}</div>
    <div class="nb-sev-mini-sub">{(0 if failed == 0 else round((int(sc.get('High', 0)) / failed) * 100))}% of fails</div>
  </div>
  <div class="nb-sev-mini med">
    <div class="nb-sev-mini-top">Medium</div>
    <div class="nb-sev-mini-val">{int(sc.get('Medium', 0)):,}</div>
    <div class="nb-sev-mini-sub">{(0 if failed == 0 else round((int(sc.get('Medium', 0)) / failed) * 100))}% of fails</div>
  </div>
  <div class="nb-sev-mini low">
    <div class="nb-sev-mini-top">Low</div>
    <div class="nb-sev-mini-val">{int(sc.get('Low', 0)):,}</div>
    <div class="nb-sev-mini-sub">{(0 if failed == 0 else round((int(sc.get('Low', 0)) / failed) * 100))}% of fails</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    st.markdown('<div class="nb-sec-hdr">Filters</div>', unsafe_allow_html=True)
    fc1, fc2 = st.columns(2)
    with fc1:
        sev_opts = SEV_ORDER
        sev_filter = st.multiselect("Severity", sev_opts, default=sev_opts, key="sev_filter")
    with fc2:
        cat_opts = sorted({f.get("category", "Uncategorized") for f in findings})
        cat_filter = st.multiselect("Category", cat_opts, default=cat_opts, key="cat_filter")

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    filtered = [
        f
        for f in findings
        if f.get("severity", "Unknown") in sev_filter and f.get("category", "Uncategorized") in cat_filter
    ]
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "Unknown"), 99))

    st.markdown(
        f"""
<div class="nb-sec-hdr" style="margin-bottom:12px;">
  Findings
  <span class="nb-count-chip">{len(filtered)} of {len(findings)}</span>
</div>
""",
        unsafe_allow_html=True,
    )

    rows_html, modals_html = build_findings_rows_html(filtered)
    st.markdown(
        f"""
<div class="nb-tbl-wrap">
  <table class="nb-table">
    <thead><tr>
      <th>Severity</th><th>Cloud</th><th>Rule ID</th><th>Check</th>
      <th>Resource ID</th><th>Region</th><th>Category</th>
      <th>Description</th><th>Remediation</th><th>Status</th>
    </tr></thead>
    <tbody>
      {rows_html if rows_html else '<tr><td colspan="10" class="nb-tbl-empty">No findings match the current filters.</td></tr>'}
    </tbody>
  </table>
</div>
{modals_html}
""",
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    _, a1, gap, a2, _ = st.columns([2.2, 1.5, 0.25, 1.5, 2.2])
    with a1:
        pdf_bytes = generate_pdf_report(report)
        if pdf_bytes:
            st.download_button(
                label="⬇  Export PDF",
                data=pdf_bytes,
                file_name=f"nebuloupe-report-{meta.get('scan_id', 'scan')}.pdf",
                mime="application/pdf",
                width="stretch",
            )
    with gap:
      st.markdown("&nbsp;", unsafe_allow_html=True)
    with a2:
        if st.button("← New Scan", key="new_scan", width="stretch"):
            st.session_state.page = "landing"
            st.session_state.results = None
            st.session_state.selected_clouds = []
            st.session_state.scanning = False
            st.rerun()

    st.markdown(
        """
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
""",
        unsafe_allow_html=True,
    )
