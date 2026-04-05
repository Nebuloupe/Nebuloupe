"""
dashboard/landing_page.py
Landing page and scan execution logic for Nebuloupe.
"""
import os
import sys
import json
import time
import uuid
import importlib
import streamlit as st
from datetime import datetime, timezone

from dashboard.icons import get_svg_icon

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

CLOUD_META = {
    "aws":   {"label": "Amazon Web Services", "icon": get_svg_icon("aws")},
    "azure": {"label": "Microsoft Azure",     "icon": get_svg_icon("azure")},
    "gcp":   {"label": "Google Cloud",        "icon": get_svg_icon("gcp")},
}


def _count_rule_files(cloud: str) -> list:
    """Return sorted list of (display_name, module_dotpath) for a cloud."""
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
    from engine.auth import get_aws_session, get_azure_credentials

    _, col, _ = st.columns([1, 1.8, 1])
    with col:
        cloud = st.session_state.selected_clouds[0]
        rule_modules = _count_rule_files(cloud)
        total = len(rule_modules) or 1

        st.markdown(
            f'<p class="nb-section-label">Scanning {total} rule files…</p>',
            unsafe_allow_html=True,
        )
        progress_bar = st.progress(0.0)
        pct_text     = st.empty()
        status_text  = st.empty()

        # Authenticate once
        auth_ctx = None
        if cloud == "aws":
            auth_ctx = get_aws_session()
        elif cloud == "azure":
            auth_ctx = get_azure_credentials()

        findings, errors = [], []
        scan_start_time = time.time()

        # Resolve real account ID
        real_account = "N/A"
        if cloud == "aws" and auth_ctx:
            try:
                real_account = auth_ctx.client("sts").get_caller_identity().get("Account", "N/A")
            except Exception:
                pass

        for idx, (display_name, mod_path) in enumerate(rule_modules):
            status_text.markdown(
                f'<p class="nb-status">'
                f'[{idx + 1}/{total}] &nbsp;'
                f'<span style="color:#c9d1d9;">{display_name}</span>'
                f'</p>',
                unsafe_allow_html=True,
            )

            if auth_ctx:
                try:
                    module = importlib.import_module(f"rules.{mod_path}")
                    findings.extend(module.run_check(auth_ctx))
                except Exception as e:
                    errors.append(str(e))

            pct = (idx + 1) / total
            progress_bar.progress(pct)
            pct_text.markdown(
                f'<p class="nb-status" style="font-size:13px;color:#00e096;">'
                f'{pct * 100:.2f}%</p>',
                unsafe_allow_html=True,
            )

        # Snap to 100%
        progress_bar.progress(1.0)
        pct_text.markdown(
            '<p class="nb-status" style="font-size:13px;color:#00e096;">100.00%</p>',
            unsafe_allow_html=True,
        )
        status_text.markdown(
            '<p class="nb-status" style="color:#00e096;">✓ &nbsp;Scan finished — loading dashboard…</p>',
            unsafe_allow_html=True,
        )

        # Build results
        sev_counts    = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        sev_score     = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
        score_total   = 0
        risk_by_cloud = {"aws": 0, "azure": 0, "gcp": 0}
        for f in findings:
            sev = f.get("severity", "Low")
            if sev in sev_counts:
                sev_counts[sev] += 1
            s = sev_score.get(sev, 0)
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

        time.sleep(0.5)

    st.session_state.results  = report
    st.session_state.scanning = False
    st.session_state.page     = "dashboard"
    st.rerun()


def page_landing():
    st.markdown("""
    <div class="nb-landing">
      <div class="nb-logo-row">
        <span class="nb-logo-icon">🔭</span>
        <span class="nb-wordmark">NEBULOUPE</span>
      </div>
      <div class="nb-tagline">Multi-Cloud Misconfiguration Scanner</div>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1, 1.8, 1])
    with col:
        is_scanning = st.session_state.scanning

        st.markdown('<p class="nb-section-label">① Select Cloud Scope</p>', unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)

        def toggle(cloud):
            if cloud in st.session_state.selected_clouds:
                st.session_state.selected_clouds = []
            else:
                st.session_state.selected_clouds = [cloud]

        for col_obj, cloud in [(c1, "aws"), (c2, "azure"), (c3, "gcp")]:
            with col_obj:
                meta = CLOUD_META[cloud]
                sel  = "selected" if cloud in st.session_state.selected_clouds else ""
                st.markdown(f"""
                <div class="nb-cloud-btn {sel}" style="pointer-events:none;">
                  <div class="nb-cloud-icon">{meta['icon']}</div>
                  <span class="nb-cloud-name">{cloud.upper()}</span>
                  <span class="nb-cloud-label">{meta['label']}</span>
                </div>""", unsafe_allow_html=True)
                if st.button(cloud.upper(), key=f"btn_{cloud}",
                             use_container_width=True, disabled=is_scanning):
                    toggle(cloud)
                    st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)

        if st.session_state.selected_clouds:
            labels = [CLOUD_META[c]["label"] for c in st.session_state.selected_clouds]
            st.markdown(
                f'<p class="nb-status">✓ &nbsp;{" · ".join(labels)}</p>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<p class="nb-status">Select one cloud provider above</p>',
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p class="nb-section-label">② Run Scan</p>', unsafe_allow_html=True)

        if is_scanning:
            _run_scan()
        else:
            scan_disabled = len(st.session_state.selected_clouds) == 0
            if st.button(
                "⚡  INITIATE SCAN" if not scan_disabled else "SELECT A CLOUD PROVIDER",
                disabled=scan_disabled,
                key="scan_btn",
                use_container_width=True,
            ):
                st.session_state.scanning = True
                st.rerun()
