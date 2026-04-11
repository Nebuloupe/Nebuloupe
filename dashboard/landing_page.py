"""
dashboard/landing_page.py  —  Nebuloupe landing page
Cloud cards are visual HTML. Streamlit buttons sit invisibly over each card
(no AWS/Azure/GCP button labels). Clicking a card selects that provider;
Initialize Scan runs the same flow as before.
"""
import os, sys, json, time, uuid, importlib, base64
import streamlit as st
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def _b64(svg_bytes):
    return "data:image/svg+xml;base64," + base64.b64encode(svg_bytes).decode()


CLOUD_DEFS = [
    ("aws",   "AWS",   "Amazon Web Services",   "#FF9900",
     _b64(b'<svg viewBox="0 0 80 50" xmlns="http://www.w3.org/2000/svg"><text x="4" y="28" font-family="Arial Black,sans-serif" font-size="22" font-weight="900" fill="#FF9900">aws</text><path d="M2 36 Q40 46 78 36" stroke="#FF9900" stroke-width="3.5" fill="none" stroke-linecap="round"/><polygon points="2,33 8,39 2,39" fill="#FF9900"/><polygon points="78,33 72,39 78,39" fill="#FF9900"/></svg>')),
    ("azure", "Azure", "Microsoft Azure",        "#60a5fa",
     _b64(b'<svg viewBox="0 0 60 50" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="ag" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0078D4"/><stop offset="1" stop-color="#50e6ff"/></linearGradient></defs><polygon points="22,4 38,4 52,46 36,46" fill="url(#ag)"/><polygon points="8,46 28,46 38,28 22,4" fill="#0078D4" opacity="0.7"/></svg>')),
    ("gcp",   "GCP",   "Google Cloud Platform",  "#a78bfa",
     _b64(b'<svg viewBox="0 0 56 56" xmlns="http://www.w3.org/2000/svg"><rect x="2" y="2" width="24" height="24" rx="4" fill="#EA4335"/><rect x="30" y="2" width="24" height="24" rx="4" fill="#4285F4"/><rect x="2" y="30" width="24" height="24" rx="4" fill="#FBBC05"/><rect x="30" y="30" width="24" height="24" rx="4" fill="#34A853"/><rect x="16" y="16" width="24" height="24" rx="3" fill="#030712"/></svg>')),
]


def _count_rule_files(cloud: str) -> list:
    rules_base = os.path.join(os.path.dirname(__file__), '..', 'rules')
    rules_path = os.path.join(rules_base, cloud)
    rule_modules = []
    if os.path.exists(rules_path):
        for root, dirs, files in os.walk(rules_path):
            for f in sorted(files):
                if f.endswith('.py') and f != '__init__.py':
                    rel = os.path.relpath(os.path.join(root, f), rules_base)
                    mod_path = os.path.splitext(rel)[0].replace(os.sep, '.')
                    rule_modules.append((f.replace('.py', ''), mod_path))
    return rule_modules


def _run_scan():
    """Run scan file-by-file, updating progress bar after each rule completes."""
    from engine.auth import get_aws_session, get_azure_credentials, get_gcp_project
    from concurrent.futures import ThreadPoolExecutor, as_completed

    _, col, _ = st.columns([1, 2, 1])
    with col:
        cloud        = st.session_state.selected_clouds[0]
        rule_modules = _count_rule_files(cloud)
        total        = len(rule_modules) or 1

        st.markdown(
            f'<div class="nb-scan-box"><div class="nb-scan-title">Scanning {total} security checks</div></div>',
            unsafe_allow_html=True,
        )
        progress_bar = st.progress(0.0)
        pct_text     = st.empty()
        status_text  = st.empty()

        auth_ctx = None
        if cloud == "aws":
            auth_ctx = get_aws_session()
        elif cloud == "azure":
            auth_ctx = get_azure_credentials()
        elif cloud == "gcp":
            auth_ctx = get_gcp_project()

        findings, errors = [], []
        scan_start_time  = time.time()

        real_account = "N/A"
        if cloud == "aws" and auth_ctx:
            try:
                real_account = auth_ctx.client("sts").get_caller_identity().get("Account", "N/A")
            except Exception:
                pass

        # Helper function to run a single rule module using the thread pool
        def _run_module(display_name, mod_path, auth_ctx):
            try:
                module = importlib.import_module(f"rules.{mod_path}")
                return display_name, module.run_check(auth_ctx), None
            except Exception as e:
                return display_name, [], str(e)

        completed_count = 0
        # Use a ThreadPoolExecutor for concurrent execution
        max_workers = min(10, total)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            if auth_ctx:
                future_to_rule = {
                    executor.submit(_run_module, display_name, mod_path, auth_ctx): display_name
                    for display_name, mod_path in rule_modules
                }
                
                for future in as_completed(future_to_rule):
                    display_name, mod_findings, error = future.result()
                    
                    if error:
                        errors.append(error)
                    else:
                        findings.extend(mod_findings)
                        
                    completed_count += 1
                    status_text.markdown(
                        f'<p class="nb-scan-status">'
                        f'<span class="nb-scan-idx">[{completed_count}/{total}]</span> '
                        f'<span class="nb-scan-rule">Completed {display_name}</span></p>',
                        unsafe_allow_html=True,
                    )
                    
                    pct = completed_count / total
                    progress_bar.progress(pct)
                    pct_text.markdown(f'<p class="nb-scan-pct">{pct * 100:.1f}%</p>', unsafe_allow_html=True)
            else:
                # If auth failed, just simulate completion
                completed_count = total
                progress_bar.progress(1.0)
                pct_text.markdown('<p class="nb-scan-pct">100%</p>', unsafe_allow_html=True)

        progress_bar.progress(1.0)
        pct_text.markdown('<p class="nb-scan-pct">100%</p>', unsafe_allow_html=True)
        status_text.markdown(
            '<p class="nb-scan-status" style="color:#14b8a6">Scan complete — loading results...</p>',
            unsafe_allow_html=True,
        )

        sev_counts    = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        sev_score     = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
        score_total   = 0
        risk_by_cloud = {"aws": 0, "azure": 0, "gcp": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in sev_counts:
                sev_counts[sev] += 1
            s  = sev_score.get(sev, 0)
            score_total += s
            pk = f.get("cloud_provider", cloud).lower()
            if pk in risk_by_cloud:
                risk_by_cloud[pk] += s

        scan_end_time      = time.time()
        scan_duration      = round(scan_end_time - scan_start_time, 2)
        scan_started_iso   = datetime.fromtimestamp(scan_start_time, tz=timezone.utc).isoformat()
        scan_completed_iso = datetime.fromtimestamp(scan_end_time,   tz=timezone.utc).isoformat()

        report = {
            "scan_metadata": {
                "scan_id":               str(uuid.uuid4()),
                "scan_started_at":       scan_started_iso,
                "scan_completed_at":     scan_completed_iso,
                "scan_duration_seconds": scan_duration,
                "cloud_scope":           cloud,
                "target_account":        real_account,
                "status":                "partial" if errors else "success",
                "errors":                errors,
            },
            "summary": {
                "total_findings":       len(findings),
                "severity_counts":      sev_counts,
                "severity_score_total": score_total,
                "risk_score_by_cloud":  risk_by_cloud,
            },
            "findings": findings,
        }

        output_path = os.path.join(os.path.dirname(__file__), '..', 'output', 'results.json')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(report, fh, indent=4)
        time.sleep(0.4)

    st.session_state.results  = report
    st.session_state.scanning = False
    st.session_state.page     = "dashboard"
    st.session_state.pop("azure_creds", None)
    st.session_state.pop("azure_needs_creds", None)
    st.rerun()


def page_landing():
    if "selected_clouds" not in st.session_state:
        st.session_state.selected_clouds = []
    if "scanning" not in st.session_state:
        st.session_state.scanning = False

    is_scanning = st.session_state.scanning
    selected    = st.session_state.selected_clouds[0] if st.session_state.selected_clouds else ""

    # ── Nav ───────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="nb-nav">
  <div class="nb-nav-logo">
    <span class="nb-nav-icon">&#128301;</span>
    <span class="nb-nav-brand">NEBULOUPE</span>
    <span class="nb-nav-tag">CSPM</span>
  </div>
  <div class="nb-nav-links">
    <span class="nb-nav-link">Docs</span>
    <span class="nb-nav-link">GitHub</span>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Hero ──────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="nb-hero-wrap">
  <div class="nb-hero-content">
    <div class="nb-hero-eyebrow"><span class="nb-eyebrow-dot"></span>Cloud Security Posture Management</div>
    <h1 class="nb-hero-title">The Intelligent<br><span class="nb-hero-accent">Multi-Cloud</span><br>Security Scanner</h1>
    <p class="nb-hero-sub">Detect misconfigurations, compliance violations, and security risks across AWS, Azure &amp; GCP &#8212; in seconds.</p>
  </div>
  <div class="nb-stats-row">
    <div class="nb-stat-item"><span class="nb-stat-n">50+</span><span class="nb-stat-l">Security Checks</span></div>
    <div class="nb-stat-div"></div>
    <div class="nb-stat-item"><span class="nb-stat-n">3</span><span class="nb-stat-l">Cloud Providers</span></div>
    <div class="nb-stat-div"></div>
    <div class="nb-stat-item"><span class="nb-stat-n">100%</span><span class="nb-stat-l">Open Source</span></div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Cloud provider selection ───────────────────────────────────────────────
    st.markdown(
        '<p class="nb-step-lbl" style="text-align:center;margin-top:8px;">&#9312; Select Cloud Provider</p>',
        unsafe_allow_html=True,
    )

    # Visual cards rendered as HTML (display only)
    _, card_col, _ = st.columns([1, 2.2, 1])
    with card_col:
        card_parts = ""
        for cloud_id, short, full, glow, img in CLOUD_DEFS:
            sel_cls = "sel" if cloud_id == selected else ""
            check   = '<div class="nb-card-check">&#10003;</div>' if cloud_id == selected else ""
            dim     = "opacity:0.4;pointer-events:none;" if is_scanning else ""
            card_parts += (
                f'<div class="nb-cloud-card {sel_cls}" style="--c:{glow};{dim}">'
                f'{check}'
                f'<div class="nb-card-glow"></div>'
                f'<div class="nb-card-3d">'
                f'<div class="nb-box-face nb-box-top"></div>'
                f'<div class="nb-box-face nb-box-front">'
                f'<img src="{img}" width="46" height="46" alt="{short}"/>'
                f'</div>'
                f'<div class="nb-box-face nb-box-right"></div>'
                f'</div>'
                f'<div class="nb-card-name">{short}</div>'
                f'<div class="nb-card-sub">{full}</div>'
                f'</div>'
            )

        if is_scanning:
            status_html = '<p class="nb-hint-text" style="color:#14b8a6;margin-top:10px;">Scanning — provider locked</p>'
        elif selected:
            sel_info    = next(c for c in CLOUD_DEFS if c[0] == selected)
            status_html = (
                f'<div class="nb-sel-status" style="margin-top:10px;">'
                f'<span class="nb-sel-dot" style="background:{sel_info[3]};box-shadow:0 0 8px {sel_info[3]};"></span>'
                f'<span class="nb-sel-text">{sel_info[2]} selected</span>'
                f'</div>'
            )
        else:
            status_html = '<p class="nb-hint-text" style="margin-top:10px;">Click a cloud card to select a provider</p>'

        st.markdown(
            f'<div class="nb-cloud-grid">{card_parts}</div>{status_html}',
            unsafe_allow_html=True,
        )

    # Invisible hit targets over each card (labels hidden — selection is via the cards only)
    _, b1, b2, b3, _ = st.columns([1, 0.73, 0.73, 0.73, 1])
    for col, (cloud_id, short, full, *_) in zip([b1, b2, b3], CLOUD_DEFS):
        with col:
            # Label is invisible via CSS; tooltip explains the control for a11y.
            if st.button(
                "\u200b",
                key=f"sel_{cloud_id}",
                help=f"Select {full}",
                use_container_width=True,
                disabled=is_scanning,
            ):
                if cloud_id == selected:
                    st.session_state.selected_clouds = []
                else:
                    st.session_state.selected_clouds = [cloud_id]
                st.rerun()

    # Only the provider overlay uses five columns; scan row has three (avoids wrong margin).
    st.markdown("""
<style>
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5)) {
    margin-top: -210px !important;
    position: relative !important;
    z-index: 10 !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5)) button {
    opacity: 0 !important;
    height: 200px !important;
    min-height: 200px !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
    cursor: pointer !important;
}
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5)) button:hover,
[data-testid="stHorizontalBlock"]:has(> div:nth-child(5)) button:focus {
    opacity: 0 !important;
    transform: none !important;
    box-shadow: none !important;
}
</style>
""", unsafe_allow_html=True)

    # ── Azure credential form (shown when needed) ─────────────────────────────
    if selected == "azure" and st.session_state.get("azure_needs_creds"):
        _, fc, _ = st.columns([1, 2.5, 1])
        with fc:
            st.markdown("""
<div style="background:#0a0f1e;border:1px solid rgba(239,68,68,0.3);border-radius:12px;padding:20px 24px;margin-bottom:16px;">
  <div style="font-size:13px;font-weight:600;color:#f87171;margin-bottom:6px;">Azure Credentials Required</div>
  <div style="font-size:11px;color:#475569;line-height:1.6;">
    Enter your Azure Service Principal credentials.<br>
    <b style="color:#64748b;">Tenant ID</b> is required.
    <b style="color:#64748b;">Client ID + Secret</b> for Service Principal auth,
    or leave blank to use browser login.
  </div>
</div>
""", unsafe_allow_html=True)
            with st.form("azure_creds_form", clear_on_submit=False):
                tenant  = st.text_input("Tenant ID *",      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", value=st.session_state.get("azure_creds", {}).get("tenant_id", ""))
                cid     = st.text_input("Client ID",         placeholder="Service Principal App ID (optional)",  value=st.session_state.get("azure_creds", {}).get("client_id", "") or "")
                csecret = st.text_input("Client Secret",     placeholder="Service Principal Secret (optional)",  type="password")
                submitted = st.form_submit_button("Save & Scan", use_container_width=True)
            if submitted:
                if not tenant:
                    st.error("Tenant ID is required.")
                else:
                    st.session_state.azure_creds = {
                        "tenant_id":     tenant.strip(),
                        "client_id":     cid.strip() or None,
                        "client_secret": csecret.strip() or None,
                    }
                    st.session_state["azure_needs_creds"] = False
                    st.session_state.scanning = True
                    st.rerun()

    # ── Scan button ───────────────────────────────────────────────────────────
    st.markdown(
        '<p class="nb-step-lbl" style="text-align:center;margin-top:24px;margin-bottom:8px;">&#9313; Initiate Security Scan</p>',
        unsafe_allow_html=True,
    )
    _, sc, _ = st.columns([1.5, 3, 1.5])
    with sc:
        if is_scanning:
            _run_scan()
        else:
            if st.button(
                "Initialize Scan",
                key="scan_btn",
                use_container_width=True,
                disabled=not selected,
            ):
                st.session_state.scanning = True
                st.rerun()

    # ── Feature cards ─────────────────────────────────────────────────────────
    st.markdown("<div style='height:56px'></div>", unsafe_allow_html=True)
    st.markdown('<p class="nb-features-lbl">What Nebuloupe Scans</p>', unsafe_allow_html=True)
    f1, f2, f3, f4 = st.columns(4)
    feats = [
        ("&#128272;", "IAM &amp; Access", "#ef4444", "Root keys, MFA, password policies, unused credentials and privilege escalation."),
        ("&#127760;", "Networking",        "#f97316", "Open security groups, VPC flow logs, NACLs, public IPs, RDP/SSH exposure."),
        ("&#128452;", "Storage",           "#eab308", "S3 public access, encryption at rest, versioning, logging, object lock."),
        ("&#128203;", "Compliance",        "#22c55e", "CIS benchmarks, encryption standards, audit logging, CloudTrail, Config rules."),
    ]
    for col, (icon, title, color, desc) in zip([f1, f2, f3, f4], feats):
        with col:
            st.markdown(
                f'<div class="nb-feat-card" style="--fc:{color};">'
                f'<div class="nb-feat-icon">{icon}</div>'
                f'<div class="nb-feat-title">{title}</div>'
                f'<div class="nb-feat-desc">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ── Footer ────────────────────────────────────────────────────────────────
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
  <div class="nb-footer-copy">Multi-Cloud Security Scanner &nbsp;&middot;&nbsp; v1.0 &nbsp;&middot;&nbsp; Open Source</div>
</div>
""", unsafe_allow_html=True)
