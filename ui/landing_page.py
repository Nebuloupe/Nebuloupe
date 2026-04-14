"""
dashboard/landing_page.py  —  Nebuloupe landing page
Cloud cards are visual HTML. Streamlit buttons sit invisibly over each card
(no AWS/Azure/GCP button labels). Clicking a card selects that provider;
Initialize Scan runs the same flow as before.
"""
import os, sys, json, time, uuid, importlib, base64, tempfile, shutil, re
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime, timezone
from ui.history_store import append_scan_history, load_scan_history

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def _svg_data_uri(file_name):
    icon_path = os.path.join(os.path.dirname(__file__), "icons", file_name)
    with open(icon_path, "rb") as icon_file:
        return "data:image/svg+xml;base64," + base64.b64encode(icon_file.read()).decode()


CLOUD_DEFS = [
    ("aws",   "AWS",   "Amazon Web Services",   "#FF9900", _svg_data_uri("aws.svg"),   70, 44),
    ("azure", "Azure", "Microsoft Azure",        "#60a5fa", _svg_data_uri("azure.svg"), 54, 54),
    ("gcp",   "GCP",   "Google Cloud Platform",  "#34A853", _svg_data_uri("gcp.svg"),   54, 54),
    (
        "terraform",
        "Terraform",
        "Terraform IaC Scan",
        "#7B42BC",
        _svg_data_uri("tf.svg"),
        56,
        56,
    ),
]

SEVERITY_CANONICAL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

_cloud_selector_component = components.declare_component(
    "cloud_selector_component",
    path=os.path.join(os.path.dirname(__file__), "components", "cloud_selector"),
)


@st.dialog("Credentials Not Found")
def _show_auth_error_popup(message: str):
    st.error("Authentication failed for the selected cloud provider.")
    st.code(message, language="text")
    if st.button("Close", key="auth_error_close", width="stretch"):
        st.session_state.auth_error_popup = None
        st.rerun()


def _render_cloud_selector(selected, disabled=False):
    clouds = [
        {
            "id": cloud_id,
            "short": short,
            "full": full,
            "glow": glow,
            "img": img,
            "w": img_w,
            "h": img_h,
        }
        for cloud_id, short, full, glow, img, img_w, img_h in CLOUD_DEFS
    ]
    return _cloud_selector_component(
        clouds=clouds,
        selected=selected,
        disabled=disabled,
        key="cloud_selector",
        default=selected or "",
    )


def _count_rule_files(cloud: str) -> list:
    if cloud == "terraform":
        rules_base = os.path.join(os.path.dirname(__file__), '..', 'rules')
        iac_paths = [
            os.path.join(rules_base, 'iac', 'aws'),
            os.path.join(rules_base, 'iac', 'azure'),
            os.path.join(rules_base, 'iac', 'gcp'),
            os.path.join(rules_base, 'iac', 'common'),
        ]
        unique_modules = {}
        for rules_path in iac_paths:
            if os.path.exists(rules_path):
                for root, dirs, files in os.walk(rules_path):
                    for f in sorted(files):
                        if f.endswith('.py') and f != '__init__.py':
                            rel = os.path.relpath(os.path.join(root, f), rules_base)
                            mod_path = os.path.splitext(rel)[0].replace(os.sep, '.')
                            unique_modules[mod_path] = (f.replace('.py', ''), mod_path)
        return list(unique_modules.values())

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


def _count_iac_rule_files(provider: str) -> list:
    rules_base = os.path.join(os.path.dirname(__file__), '..', 'rules')
    iac_paths = [
        os.path.join(rules_base, 'iac', provider),
        os.path.join(rules_base, 'iac', 'common'),
    ]

    unique_modules = {}
    for rules_path in iac_paths:
        if os.path.exists(rules_path):
            for root, dirs, files in os.walk(rules_path):
                for f in sorted(files):
                    if f.endswith('.py') and f != '__init__.py':
                        rel = os.path.relpath(os.path.join(root, f), rules_base)
                        mod_path = os.path.splitext(rel)[0].replace(os.sep, '.')
                        unique_modules[mod_path] = (f.replace('.py', ''), mod_path)
    return list(unique_modules.values())


def _pick_terraform_file_via_os_dialog() -> str:
    try:
        from tkinter import Tk, filedialog

        root = Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Select Terraform file",
            filetypes=[("Terraform files", "*.tf *.tf.json"), ("All files", "*.*")],
        )
        root.destroy()
        return selected
    except Exception:
        return ""


def _detect_tf_cloud_provider(tf_file_path: str) -> str:
    """Infer cloud provider from Terraform file content."""
    try:
        with open(tf_file_path, "r", encoding="utf-8") as fh:
            content = fh.read().lower()
    except Exception:
        return ""

    # Prefer explicit provider blocks first.
    provider_patterns = {
        "aws": r'provider\s+"aws"',
        "azure": r'provider\s+"azurerm"',
        "gcp": r'provider\s+"google"',
    }
    for provider, pattern in provider_patterns.items():
        if re.search(pattern, content):
            return provider

    # Fallback to resource/data prefixes when provider block is absent.
    prefix_patterns = {
        "aws": [r'\bresource\s+"aws_', r'\bdata\s+"aws_'],
        "azure": [r'\bresource\s+"azurerm_', r'\bdata\s+"azurerm_'],
        "gcp": [r'\bresource\s+"google_', r'\bdata\s+"google_'],
    }

    matches = []
    for provider, patterns in prefix_patterns.items():
        if any(re.search(p, content) for p in patterns):
            matches.append(provider)

    if len(matches) == 1:
        return matches[0]
    return ""


def _normalize_finding(finding: dict, default_provider: str = "") -> dict:
    if not isinstance(finding, dict):
        return {}

    normalized = dict(finding)

    status = str(normalized.get("status", "")).strip().upper()
    if status:
        normalized["status"] = status

    severity_raw = str(normalized.get("severity", "Low")).strip().lower()
    normalized["severity"] = SEVERITY_CANONICAL.get(severity_raw, "Low")

    region_raw = normalized.get("region", "")
    region = str(region_raw).strip().lower()
    normalized["region"] = region if region else "global"

    provider_raw = normalized.get("cloud_provider", default_provider)
    provider = str(provider_raw).strip().lower()
    if provider:
        normalized["cloud_provider"] = provider

    return normalized


def _run_scan():
    """Run scan file-by-file, updating progress bar after each rule completes."""
    from engine.auth import AuthError, get_aws_session, get_azure_credentials, get_gcp_project
    from engine.core_loop import start_iac_scan
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _render_progress(progress_slot, pct):
        pct = max(0.0, min(1.0, float(pct)))
        progress_slot.markdown(
            (
                '<div class="nb-shad-progress" role="progressbar" '
                f'aria-valuemin="0" aria-valuemax="100" aria-valuenow="{pct * 100:.1f}">'
                f'<div class="nb-shad-progress-fill" style="width:{pct * 100:.1f}%"></div>'
                '</div>'
            ),
            unsafe_allow_html=True,
        )

    _, col, _ = st.columns([1, 2, 1])
    with col:
        cloud = st.session_state.selected_clouds[0]
        detected_cloud = ""

        if cloud == "terraform":
            selected_tf = st.session_state.get("terraform_selected_file", "")
            if not selected_tf or not os.path.isfile(selected_tf):
                st.session_state.scanning = False
                st.session_state.auth_error_popup = "[!] Terraform file was not found. Please select a valid .tf file and try again."
                st.rerun()

            detected_cloud = _detect_tf_cloud_provider(selected_tf)
            if not detected_cloud:
                st.session_state.scanning = False
                st.session_state.auth_error_popup = (
                    "[!] Could not detect cloud provider from the selected Terraform file. "
                    "Use a file containing AWS, AzureRM, or Google provider/resource definitions."
                )
                st.rerun()

            rule_modules = _count_iac_rule_files(detected_cloud)
        else:
            rule_modules = _count_rule_files(cloud)

        total = len(rule_modules) or 1

        st.markdown(
            f'<div class="nb-scan-box"><div class="nb-scan-title">Scanning {total} security checks</div></div>',
            unsafe_allow_html=True,
        )
        progress_slot = st.empty()
        _render_progress(progress_slot, 0.0)
        pct_text     = st.empty()
        status_text  = st.empty()

        if cloud == "terraform":
            selected_tf = st.session_state.get("terraform_selected_file", "")
            temp_scan_dir = tempfile.mkdtemp(prefix="nebuloupe_tf_")
            try:
                tf_name = os.path.basename(selected_tf)
                shutil.copy2(selected_tf, os.path.join(temp_scan_dir, tf_name))

                status_text.markdown(
                    f'<p class="nb-scan-status"><span class="nb-scan-idx">[1/1]</span> '
                    f'<span class="nb-scan-rule">Analyzing {tf_name} ({detected_cloud.upper()})</span></p>',
                    unsafe_allow_html=True,
                )
                _render_progress(progress_slot, 0.35)
                pct_text.markdown('<p class="nb-scan-pct">35.0%</p>', unsafe_allow_html=True)

                report = start_iac_scan(cloud_scope=detected_cloud, tf_path=temp_scan_dir)
                if not report:
                    raise RuntimeError("IaC scan returned no report")

                findings = report.get("findings", [])
                errors = report.get("scan_metadata", {}).get("errors", [])
                report.setdefault("scan_metadata", {})["cloud_scope"] = detected_cloud
                report["scan_metadata"]["target_account"] = selected_tf
                report["scan_metadata"]["terraform_file"] = selected_tf
                report["scan_metadata"]["scan_entrypoint"] = "terraform"

                _render_progress(progress_slot, 1.0)
                pct_text.markdown('<p class="nb-scan-pct">100%</p>', unsafe_allow_html=True)
                status_text.markdown(
                    '<p class="nb-scan-status" style="color:#14b8a6">Terraform scan complete — loading results...</p>',
                    unsafe_allow_html=True,
                )

                output_path = os.path.join(os.path.dirname(__file__), '..', 'output', 'results.json')
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, "w") as fh:
                    json.dump(report, fh, indent=4)

                append_scan_history(report)
                time.sleep(0.4)
            except Exception as e:
                st.session_state.scanning = False
                st.session_state.auth_error_popup = f"[!] Terraform scan failed: {e}"
                st.rerun()
            finally:
                try:
                    shutil.rmtree(temp_scan_dir, ignore_errors=True)
                except Exception:
                    pass

            st.session_state.results = report
            st.session_state.scanning = False
            st.session_state.page = "dashboard"
            st.rerun()

        auth_ctx = None
        try:
            if cloud == "aws":
                auth_ctx = get_aws_session()
            elif cloud == "azure":
                auth_ctx = get_azure_credentials()
            elif cloud == "gcp":
                auth_ctx = get_gcp_project()
        except AuthError as e:
            st.session_state.scanning = False
            st.session_state.auth_error_popup = str(e)
            st.rerun()
        except Exception as e:
            st.session_state.scanning = False
            st.session_state.auth_error_popup = f"[!] Authentication failed: {e}"
            st.rerun()

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
                        findings.extend(
                            _normalize_finding(finding, cloud)
                            for finding in mod_findings
                            if isinstance(finding, dict)
                        )
                        
                    completed_count += 1
                    status_text.markdown(
                        f'<p class="nb-scan-status">'
                        f'<span class="nb-scan-idx">[{completed_count}/{total}]</span> '
                        f'<span class="nb-scan-rule">Completed {display_name}</span></p>',
                        unsafe_allow_html=True,
                    )
                    
                    pct = completed_count / total
                    _render_progress(progress_slot, pct)
                    pct_text.markdown(f'<p class="nb-scan-pct">{pct * 100:.1f}%</p>', unsafe_allow_html=True)
            else:
                # If auth failed, just simulate completion
                completed_count = total
                _render_progress(progress_slot, 1.0)
                pct_text.markdown('<p class="nb-scan-pct">100%</p>', unsafe_allow_html=True)

        _render_progress(progress_slot, 1.0)
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
            if str(f.get("status", "")).upper() != "FAIL":
                continue

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

        append_scan_history(report)
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
    if "auth_error_popup" not in st.session_state:
        st.session_state.auth_error_popup = None
    if "terraform_selected_file" not in st.session_state:
        st.session_state.terraform_selected_file = ""

    if st.session_state.auth_error_popup:
        _show_auth_error_popup(st.session_state.auth_error_popup)

    is_scanning = st.session_state.scanning
    selected    = st.session_state.selected_clouds[0] if st.session_state.selected_clouds else ""
    if "show_history_panel" not in st.session_state:
        st.session_state.show_history_panel = False

    nav_history = st.query_params.get("history")
    if nav_history == "1":
        st.session_state.show_history_panel = True
        try:
            del st.query_params["history"]
        except Exception:
            pass
        st.rerun()

    # ── Nav ───────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="nb-nav">
  <div class="nb-nav-logo">
    <span class="nb-nav-icon">&#128301;</span>
    <span class="nb-nav-brand">NEBULOUPE</span>    <span class="nb-nav-tag">CMSS</span>
  </div>
    <div class="nb-nav-actions">
                <form method="get" target="_self" style="margin:0;">
                        <input type="hidden" name="history" value="1" />
                        <button type="submit" class="nb-nav-history">Scan History</button>
                </form>
    </div>
</div>
""", unsafe_allow_html=True)

    if st.session_state.show_history_panel:
        st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)
        st.markdown(
            """
<style>
div[class*="st-key-inline_hist_row_"] button {
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
div[class*="st-key-inline_hist_row_"] button::before,
div[class*="st-key-inline_hist_row_"] button::after {
    content: none !important;
    display: none !important;
}
div[class*="st-key-inline_hist_row_"] button:hover {
    transform: none !important;
    border-color: #334155 !important;
    background: #0b1220 !important;
    box-shadow: none !important;
}
div[class*="st-key-inline_hist_row_"] button > div {
    width: 100% !important;
    display: block !important;
    text-align: left !important;
}
div[class*="st-key-inline_hist_row_"] button p {
    margin: 0 !important;
    text-align: left !important;
}
</style>
""",
        unsafe_allow_html=True,
    )

        top_l, top_r = st.columns([4.5, 1.2])
        with top_l:
            st.markdown('<div class="nb-sec-hdr">Previous Scans</div>', unsafe_allow_html=True)
        with top_r:
            if st.button("Close", key="close_history_panel", width="stretch"):
                st.session_state.show_history_panel = False
                st.rerun()

        history = load_scan_history()
        if not history:
            st.info("No previous scans found yet. Run a scan to populate history.")
        else:
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
                if st.button(row_label, key=f"inline_hist_row_{i}", width="stretch"):
                    st.session_state.results = item.get("report")
                    st.session_state.page = "dashboard"
                    st.rerun()

                st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Keep history as an inline view on landing page.
        return

    # ── Hero ──────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="nb-hero-wrap">
  <div class="nb-hero-content">
        <div class="nb-hero-eyebrow"><span class="nb-eyebrow-dot"></span>Cloud Misconfiguration Security Scanner</div>
        <h1 class="nb-hero-title">The Intelligent<br><span class="nb-hero-accent">Multi-Cloud</span><br>Security Scanner</h1>
    <p class="nb-hero-sub">Detect misconfigurations, compliance violations, and security risks across AWS, Azure, GCP, and Terraform IaC &#8212; in seconds.</p>
  </div>
  <div class="nb-stats-row">
    <div class="nb-stat-item"><span class="nb-stat-n">50+</span><span class="nb-stat-l">Security Checks</span></div>
    <div class="nb-stat-div"></div>
    <div class="nb-stat-item"><span class="nb-stat-n">4</span><span class="nb-stat-l">Scan Targets</span></div>
    <div class="nb-stat-div"></div>
    <div class="nb-stat-item"><span class="nb-stat-n">100%</span><span class="nb-stat-l">Open Source</span></div>
  </div>
</div>
""", unsafe_allow_html=True)

    # ── Cloud provider selection ───────────────────────────────────────────────
    st.markdown(
        '<p class="nb-step-lbl" style="text-align:center;margin-top:8px;">&#9312; Select Scan Target</p>',
        unsafe_allow_html=True,
    )

    # Visual cards rendered by a custom component (clickable cards, no browser redirect/new tab)
    _, card_col, _ = st.columns([1, 2.2, 1])
    with card_col:
        selected_from_component = _render_cloud_selector(selected=selected, disabled=is_scanning)
        if (
            selected_from_component
            and selected_from_component in {"aws", "azure", "gcp", "terraform"}
            and selected_from_component != selected
            and not is_scanning
        ):
            st.session_state.selected_clouds = [selected_from_component]
            st.rerun()

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
                submitted = st.form_submit_button("Save & Scan", width="stretch")
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
                width="stretch",
                disabled=not selected,
            ):
                if selected == "terraform":
                    selected_tf_file = _pick_terraform_file_via_os_dialog()
                    if not selected_tf_file:
                        st.warning("Terraform file selection was cancelled.")
                        return
                    st.session_state.terraform_selected_file = selected_tf_file
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
    <div class="nb-footer-copy">Cloud Misconfiguration Security Scanner &nbsp;&middot;&nbsp; v1.0 &nbsp;&middot;&nbsp; Open Source</div>
</div>
""", unsafe_allow_html=True)
