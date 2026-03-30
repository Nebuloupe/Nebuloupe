import streamlit as st
import json
import sys
import os
import plotly.graph_objects as go

# Ensure engine module can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from engine.scanner import run_scanner
import time
import random
import uuid
from datetime import datetime, timezone

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Nebuloupe · Cloud Security Scanner",
    page_icon="🔭",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;700;800&display=swap');

/* ── Reset & base ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, [data-testid="stAppViewContainer"] {
    background: #080b10 !important;
    color: #c9d1d9 !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* hide default streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
[data-testid="stToolbar"] { display: none; }
[data-testid="stDecoration"] { display: none; }
section[data-testid="stSidebar"] { display: none; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #21262d; border-radius: 3px; }

/* ── Adjust streamlit padding ── */
.block-container {
    padding: 2rem 4rem !important;
    max-width: 100% !important;
}

/* ── LANDING PAGE ── */
.nb-landing {
    margin-top: 0;
    margin-bottom: 0.5rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 40px 20px;
    background:
        radial-gradient(ellipse 80% 50% at 50% -10%, rgba(0,200,150,0.08) 0%, transparent 60%),
        radial-gradient(ellipse 60% 40% at 80% 80%, rgba(0,120,255,0.06) 0%, transparent 50%),
        #080b10;
    position: relative;
    overflow: hidden;
}

/* grid overlay */
.nb-landing::before {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
        linear-gradient(rgba(0,200,150,0.04) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,200,150,0.04) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
}

.nb-logo-row {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 8px;
}

.nb-logo-icon {
    font-size: 36px;
    filter: drop-shadow(0 0 16px rgba(0,220,160,0.7));
}

.nb-wordmark {
    font-family: 'Syne', sans-serif;
    font-size: 42px;
    font-weight: 800;
    letter-spacing: -1px;
    background: linear-gradient(135deg, #00e096 0%, #00aaff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    line-height: 1;
}

.nb-tagline {
    font-size: 12px;
    font-weight: 300;
    color: #58a6a6;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 52px;
    text-align: center;
}

.nb-card {
    background: rgba(13, 17, 23, 0.85);
    border: 1px solid #21262d;
    border-radius: 16px;
    padding: 40px 44px;
    width: 100%;
    max-width: 580px;
    backdrop-filter: blur(12px);
    box-shadow: 0 0 0 1px rgba(0,200,150,0.06), 0 32px 64px rgba(0,0,0,0.6);
    position: relative;
    z-index: 1;
}

.nb-section-label {
    font-size: 10px;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    color: #444c56;
    margin-bottom: 16px;
    font-weight: 600;
}

/* ── Cloud selector buttons ── */
.nb-cloud-row {
    display: flex;
    gap: 12px;
    margin-bottom: 32px;
}

.nb-cloud-btn {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 18px 12px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 10px;
    cursor: pointer;
    transition: all 0.2s ease;
    color: #8b949e;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 1px;
    font-weight: 600;
    text-transform: uppercase;
}
.nb-cloud-btn:hover {
    border-color: #00e096;
    color: #00e096;
    background: rgba(0,224,150,0.05);
    transform: translateY(-2px);
}
.nb-cloud-btn.selected {
    border-color: #00e096;
    color: #00e096;
    background: rgba(0,224,150,0.08);
    box-shadow: 0 0 20px rgba(0,224,150,0.15);
}
.nb-cloud-icon { font-size: 26px; }

/* ── Scan button ── */
.nb-scan-btn-wrap { margin-top: 4px; }
.stButton > button {
    width: 100%;
    padding: 16px 32px !important;
    background: linear-gradient(135deg, #00c87a, #00aaff) !important;
    color: #080b10 !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 15px !important;
    font-weight: 800 !important;
    letter-spacing: 1px !important;
    text-transform: uppercase !important;
    border: none !important;
    border-radius: 10px !important;
    cursor: pointer !important;
    transition: all 0.2s ease !important;
    box-shadow: 0 4px 24px rgba(0,200,150,0.3) !important;
}
.stButton > button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 8px 32px rgba(0,200,150,0.45) !important;
    filter: brightness(1.05) !important;
}
.stButton > button:disabled {
    background: #21262d !important;
    color: #444c56 !important;
    cursor: not-allowed !important;
    box-shadow: none !important;
    transform: none !important;
}

/* ── Progress bar ── */
.stProgress > div > div > div {
    background: linear-gradient(90deg, #00c87a, #00aaff) !important;
    border-radius: 4px !important;
}
.stProgress > div > div {
    background: #161b22 !important;
    border-radius: 4px !important;
    height: 8px !important;
}

/* ── Status text ── */
.nb-status {
    font-size: 11px;
    color: #58a6a6;
    letter-spacing: 1px;
    text-align: center;
    min-height: 18px;
    margin-top: 8px;
}

/* ── DASHBOARD ── */
.nb-dash-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 32px;
    border-bottom: 1px solid #21262d;
    background: rgba(8,11,16,0.95);
    backdrop-filter: blur(8px);
    position: sticky;
    top: 0;
    z-index: 100;
}
.nb-dash-logo {
    font-family: 'Syne', sans-serif;
    font-size: 20px;
    font-weight: 800;
    background: linear-gradient(135deg, #00e096, #00aaff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}
.nb-dash-meta {
    font-size: 11px;
    color: #444c56;
    letter-spacing: 1px;
    text-align: right;
    line-height: 1.6;
}
.nb-dash-meta span { color: #58a6a6; }

/* ── Stat cards ── */
.nb-stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    padding: 28px 32px 0;
}
.nb-stat-card {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 20px 24px;
    position: relative;
    overflow: hidden;
}
.nb-stat-card::after {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
}
.nb-stat-card.critical::after { background: #f85149; }
.nb-stat-card.high::after     { background: #e3703b; }
.nb-stat-card.medium::after   { background: #e3b341; }
.nb-stat-card.low::after      { background: #3fb950; }
.nb-stat-card.total::after    { background: linear-gradient(90deg, #00e096, #00aaff); }

.nb-stat-label {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #444c56;
    margin-bottom: 8px;
    font-weight: 600;
}
.nb-stat-value {
    font-family: 'Syne', sans-serif;
    font-size: 36px;
    font-weight: 800;
    line-height: 1;
}
.nb-stat-value.critical { color: #f85149; }
.nb-stat-value.high     { color: #e3703b; }
.nb-stat-value.medium   { color: #e3b341; }
.nb-stat-value.low      { color: #3fb950; }
.nb-stat-value.total    { color: #c9d1d9; }
.nb-stat-sub {
    font-size: 11px;
    color: #444c56;
    margin-top: 4px;
}

/* ── Findings table ── */
.nb-findings-section {
    padding: 28px 32px;
}
.nb-findings-title {
    font-family: 'Syne', sans-serif;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #8b949e;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.nb-findings-title::before {
    content: '';
    display: inline-block;
    width: 3px;
    height: 14px;
    background: linear-gradient(#00e096, #00aaff);
    border-radius: 2px;
}

.nb-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}
.nb-table thead tr {
    background: #0d1117;
    border-bottom: 1px solid #21262d;
}
.nb-table th {
    padding: 12px 16px;
    text-align: left;
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: #444c56;
    font-weight: 600;
    white-space: nowrap;
}
.nb-table tbody tr {
    border-bottom: 1px solid #161b22;
    transition: background 0.15s;
}
.nb-table tbody tr:hover { background: rgba(0,200,150,0.03); }
.nb-table td {
    padding: 13px 16px;
    color: #8b949e;
    vertical-align: middle;
}
.nb-table td.resource { color: #c9d1d9; font-weight: 400; }
.nb-table td.desc { color: #8b949e; max-width: 320px; }

/* severity pills */
.nb-pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    white-space: nowrap;
}
.nb-pill.Critical { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.nb-pill.High     { background: rgba(227,112,59,0.15); color: #e3703b; border: 1px solid rgba(227,112,59,0.3); }
.nb-pill.Medium   { background: rgba(227,179,65,0.15); color: #e3b341; border: 1px solid rgba(227,179,65,0.3); }
.nb-pill.Low      { background: rgba(63,185,80,0.15);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }

/* cloud badges */
.nb-cloud-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    letter-spacing: 0.5px;
    font-weight: 600;
    text-transform: uppercase;
}
.nb-cloud-badge.aws   { background: rgba(255,153,0,0.1);  color: #ff9900; border: 1px solid rgba(255,153,0,0.25); }
.nb-cloud-badge.azure { background: rgba(0,120,212,0.1);  color: #2196f3; border: 1px solid rgba(0,120,212,0.25); }
.nb-cloud-badge.gcp   { background: rgba(66,133,244,0.1); color: #4285f4; border: 1px solid rgba(66,133,244,0.25); }

/* status */
.nb-status-pill {
    display: inline-flex; align-items: center; gap: 4px;
    font-size: 10px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
}
.nb-status-pill.FAIL { color: #f85149; }
.nb-status-pill.PASS { color: #3fb950; }
.nb-status-pill.FAIL::before { content: '●'; font-size: 8px; }
.nb-status-pill.PASS::before { content: '●'; font-size: 8px; }

/* ── scan-again button ── */
.nb-rescan-btn > div > button {
    background: transparent !important;
    border: 1px solid #21262d !important;
    color: #8b949e !important;
    font-size: 12px !important;
    padding: 10px 20px !important;
    box-shadow: none !important;
}
.nb-rescan-btn > div > button:hover {
    border-color: #00e096 !important;
    color: #00e096 !important;
    transform: none !important;
}

/* ── misc streamlit overrides ── */
.stSelectbox label, .stMultiSelect label { color: #58a6a6 !important; font-size: 11px !important; }
[data-testid="stSelectbox"] > div > div {
    background: #0d1117 !important;
    border-color: #21262d !important;
    color: #c9d1d9 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# MOCK DATA GENERATOR
# ─────────────────────────────────────────────
MOCK_FINDINGS = {
    "aws": [
        {"rule_id":"AWS-S3-001","check":"S3 Bucket Public Access Block Disabled","severity":"Critical","resource_type":"aws::s3::bucket","resource_id":"prod-data-backup-2024","region":"us-east-1","description":"S3 bucket has public access block disabled, exposing objects to the internet.","status":"FAIL","category":"Data Exposure"},
        {"rule_id":"AWS-IAM-002","check":"Root Account MFA Not Enabled","severity":"Critical","resource_type":"aws::iam::root","resource_id":"123456789012","region":"global","description":"AWS root account does not have MFA enabled. Critical account takeover risk.","status":"FAIL","category":"Identity & Access"},
        {"rule_id":"AWS-EC2-003","check":"Security Group Allows SSH from 0.0.0.0/0","severity":"High","resource_type":"aws::ec2::securitygroup","resource_id":"sg-0a1b2c3d4e5f","region":"us-west-2","description":"Security group permits inbound SSH (port 22) from any IP address.","status":"FAIL","category":"Network"},
        {"rule_id":"AWS-S3-004","check":"S3 Bucket Server-Side Encryption Disabled","severity":"High","resource_type":"aws::s3::bucket","resource_id":"static-assets-prod","region":"eu-west-1","description":"Bucket does not enforce server-side encryption at rest.","status":"FAIL","category":"Encryption"},
        {"rule_id":"AWS-IAM-005","check":"IAM User Access Key Not Rotated >90d","severity":"Medium","resource_type":"aws::iam::user","resource_id":"svc-deploy-bot","region":"global","description":"Access key has not been rotated in over 90 days.","status":"FAIL","category":"Identity & Access"},
        {"rule_id":"AWS-EC2-006","check":"EBS Volume Not Encrypted","severity":"Medium","resource_type":"aws::ec2::volume","resource_id":"vol-09f8e7d6c5b4","region":"us-east-1","description":"EBS volume is not encrypted, data at rest is exposed if volume is detached.","status":"FAIL","category":"Encryption"},
        {"rule_id":"AWS-S3-007","check":"S3 Bucket Versioning Disabled","severity":"Low","resource_type":"aws::s3::bucket","resource_id":"log-archive-old","region":"us-east-1","description":"Bucket versioning is not enabled; accidental deletions are unrecoverable.","status":"FAIL","category":"Data Protection"},
    ],
    "azure": [
        {"rule_id":"AZ-BLOB-001","check":"Blob Container Allows Public Access","severity":"Critical","resource_type":"azure::storage::blobcontainer","resource_id":"storageaccount/publicfiles","region":"eastus","description":"Blob container has anonymous public read access enabled.","status":"FAIL","category":"Data Exposure"},
        {"rule_id":"AZ-NSG-002","check":"NSG Allows RDP from Internet","severity":"High","resource_type":"azure::network::nsg","resource_id":"nsg-prod-vm-01","region":"westeurope","description":"Network Security Group allows inbound RDP (port 3389) from 0.0.0.0/0.","status":"FAIL","category":"Network"},
        {"rule_id":"AZ-IAM-003","check":"Subscription Has >3 Owners","severity":"High","resource_type":"azure::authorization::roleassignment","resource_id":"sub-abcd1234","region":"global","description":"Subscription has 5 owner-level role assignments, exceeding recommended maximum of 3.","status":"FAIL","category":"Identity & Access"},
        {"rule_id":"AZ-SQL-004","check":"Azure SQL Auditing Disabled","severity":"Medium","resource_type":"azure::sql::server","resource_id":"sql-prod-eastus","region":"eastus","description":"Auditing is not enabled on the SQL Server, limiting threat detection capability.","status":"FAIL","category":"Logging"},
        {"rule_id":"AZ-KV-005","check":"Key Vault Soft Delete Disabled","severity":"Low","resource_type":"azure::keyvault::vault","resource_id":"kv-secrets-main","region":"uksouth","description":"Key Vault does not have soft-delete enabled; secrets can be permanently lost.","status":"FAIL","category":"Data Protection"},
    ],
    "gcp": [
        {"rule_id":"GCP-GCS-001","check":"Cloud Storage Bucket Publicly Accessible","severity":"Critical","resource_type":"gcp::storage::bucket","resource_id":"gs://data-exports-prod","region":"us-central1","description":"Bucket has allUsers IAM binding, making all objects publicly readable.","status":"FAIL","category":"Data Exposure"},
        {"rule_id":"GCP-FW-002","check":"VPC Firewall Allows SSH from 0.0.0.0/0","severity":"High","resource_type":"gcp::compute::firewall","resource_id":"default-allow-ssh","region":"global","description":"Firewall rule permits unrestricted SSH inbound access from any source.","status":"FAIL","category":"Network"},
        {"rule_id":"GCP-SA-003","check":"Service Account Key Age >90 Days","severity":"High","resource_type":"gcp::iam::serviceaccountkey","resource_id":"svc-data-pipeline@proj.iam","region":"global","description":"Service account key has not been rotated in 127 days.","status":"FAIL","category":"Identity & Access"},
        {"rule_id":"GCP-SQL-004","check":"Cloud SQL Instance Publicly Exposed","severity":"Medium","resource_type":"gcp::sql::instance","resource_id":"db-prod-main","region":"us-east1","description":"Cloud SQL authorized network includes 0.0.0.0/0, allowing unrestricted access.","status":"FAIL","category":"Network"},
    ],
}

CLOUD_META = {
    "aws":   {"icon": "🟠", "label": "Amazon Web Services", "color": "#ff9900"},
    "azure": {"icon": "🔵", "label": "Microsoft Azure",     "color": "#2196f3"},
    "gcp":   {"icon": "🟢", "label": "Google Cloud",        "color": "#4285f4"},
}

SCAN_STEPS = [
    "Authenticating with cloud provider...",
    "Enumerating cloud resources...",
    "Loading rule plugins...",
    "Executing IAM checks...",
    "Executing network / firewall checks...",
    "Executing storage checks...",
    "Executing encryption checks...",
    "Executing logging & monitoring checks...",
    "Scoring findings by severity...",
    "Writing output/results.json...",
    "Scan complete.",
]

SEV_ORDER = ["Critical", "High", "Medium", "Low"]
SEV_SCORE = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}


def make_findings(clouds):
    all_findings = []
    for c in clouds:
        for f in MOCK_FINDINGS.get(c, []):
            all_findings.append({**f, "cloud_provider": c})
    return all_findings


def make_results_json(clouds, findings, duration):
    severity_counts = {s: sum(1 for f in findings if f.get("severity") == s) for s in SEV_ORDER}
    score_total = sum(SEV_SCORE.get(f.get("severity", "Low"), 0) for f in findings)
    risk_by_cloud = {
        c: sum(
            SEV_SCORE.get(f.get("severity", "Low"), 0)
            for f in findings
            if f.get("cloud_provider") == c
        )
        for c in ["aws", "azure", "gcp"]
    }
    return {
        "scan_metadata": {
            "scan_id": str(uuid.uuid4()),
            "scan_started_at": datetime.now(timezone.utc).isoformat(),
            "scan_completed_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": round(duration, 2),
            "cloud_scope": "|".join(clouds) if len(clouds) < 3 else "all",
            "target_account": "demo-account-001",
            "status": "success",
            "errors": [],
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "severity_score_total": score_total,
            "risk_score_by_cloud": risk_by_cloud,
        },
        "findings": findings,
    }


# ─────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────
if "page" not in st.session_state:
    st.session_state.page = "landing"
if "selected_clouds" not in st.session_state:
    st.session_state.selected_clouds = []
if "results" not in st.session_state:
    st.session_state.results = None


# ─────────────────────────────────────────────
# ── PAGE 1: LANDING ───────────────────────────
# ─────────────────────────────────────────────
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

    # We'll render the card manually via st columns trick
    # Centre column
    _, col, _ = st.columns([1, 1.8, 1])

    with col:
        # ── Cloud selector ──
        st.markdown('<p class="nb-section-label">① Select Cloud Scope</p>', unsafe_allow_html=True)

        c1, c2, c3 = st.columns(3)

        def toggle(cloud):
            if cloud in st.session_state.selected_clouds:
                st.session_state.selected_clouds.remove(cloud)
            else:
                st.session_state.selected_clouds.append(cloud)

        with c1:
            sel = "selected" if "aws" in st.session_state.selected_clouds else ""
            st.markdown(f"""
            <div class="nb-cloud-btn {sel}" style="pointer-events:none;">
              <span class="nb-cloud-icon">🟠</span>AWS
            </div>""", unsafe_allow_html=True)
            if st.button("AWS", key="btn_aws", use_container_width=True):
                toggle("aws")
                st.rerun()

        with c2:
            sel = "selected" if "azure" in st.session_state.selected_clouds else ""
            st.markdown(f"""
            <div class="nb-cloud-btn {sel}" style="pointer-events:none;">
              <span class="nb-cloud-icon">🔵</span>Azure
            </div>""", unsafe_allow_html=True)
            if st.button("Azure", key="btn_azure", use_container_width=True):
                toggle("azure")
                st.rerun()

        with c3:
            sel = "selected" if "gcp" in st.session_state.selected_clouds else ""
            st.markdown(f"""
            <div class="nb-cloud-btn {sel}" style="pointer-events:none;">
              <span class="nb-cloud-icon">🟢</span>GCP
            </div>""", unsafe_allow_html=True)
            if st.button("GCP", key="btn_gcp", use_container_width=True):
                toggle("gcp")
                st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)

        # Selection status
        if st.session_state.selected_clouds:
            labels = [CLOUD_META[c]["label"] for c in st.session_state.selected_clouds]
            st.markdown(
                f'<p class="nb-status">✓ &nbsp;{" · ".join(labels)}</p>',
                unsafe_allow_html=True
            )
        else:
            st.markdown('<p class="nb-status">Select one or more cloud providers above</p>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<p class="nb-section-label">② Run Scan</p>', unsafe_allow_html=True)

        scan_disabled = len(st.session_state.selected_clouds) == 0
        if st.button(
            "⚡  INITIATE SCAN" if not scan_disabled else "SELECT A CLOUD PROVIDER",
            disabled=scan_disabled,
            key="scan_btn",
            use_container_width=True,
        ):
            run_scan()


def run_scan():
    """Run actual scan with animated progress then navigate to dashboard."""
    _, col, _ = st.columns([1, 1.8, 1])
    with col:
        st.markdown('<p class="nb-section-label">Scanning…</p>', unsafe_allow_html=True)
        progress_bar = st.progress(0)
        status_text  = st.empty()

        status_text.markdown('<p class="nb-status">Authenticating and scanning targeted clouds...</p>', unsafe_allow_html=True)
        progress_bar.progress(50)
        
        # Trigger real scan
        for cloud in st.session_state.selected_clouds:
            run_scanner(cloud)
            
        progress_bar.progress(100)
        status_text.markdown('<p class="nb-status" style="color:#00e096;">✓ &nbsp;Scan finished — loading dashboard…</p>', unsafe_allow_html=True)
        time.sleep(0.6)

    # Load real results
    results_path = os.path.join(os.path.dirname(__file__), '..', 'output', 'results.json')
    try:
        with open(results_path, "r") as f:
            st.session_state.results = json.load(f)
    except:
        st.error("Could not find previous scan results in output/results.json")
        return
        
    st.session_state.page = "dashboard"
    st.rerun()


# ─────────────────────────────────────────────
# ── PAGE 2: DASHBOARD ─────────────────────────
# ─────────────────────────────────────────────
def page_dashboard():
    r = st.session_state.results
    meta      = r["scan_metadata"]
    summary   = r["summary"]
    findings  = r["findings"]

    sc = summary["severity_counts"]
    scope_str = meta["cloud_scope"].upper()
    dur_str   = f"{meta['scan_duration_seconds']}s"
    ts        = meta["scan_started_at"][:19].replace("T", " ") + " UTC"

    # ── Header ──
    col_left, col_right = st.columns([3, 1])
    with col_left:
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:12px;padding:20px 0 0 8px;">
          <span style="font-size:28px;filter:drop-shadow(0 0 10px rgba(0,220,160,0.6))">🔭</span>
          <span class="nb-dash-logo">NEBULOUPE</span>
          <span style="font-size:11px;color:#444c56;letter-spacing:2px;text-transform:uppercase;margin-left:8px;">
            / FINDINGS DASHBOARD
          </span>
        </div>
        """, unsafe_allow_html=True)
    with col_right:
        st.markdown(f"""
        <div class="nb-dash-meta" style="padding:20px 8px 0 0;text-align:right;">
          Scope: <span>{scope_str}</span>&nbsp;&nbsp;·&nbsp;&nbsp;
          Duration: <span>{dur_str}</span><br>
          <span style="font-size:10px;">{ts}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<hr style="border:none;border-top:1px solid #21262d;margin:12px 0 0;">', unsafe_allow_html=True)

    # ── Stat Cards ──
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    s1, s2, s3, s4, s5 = st.columns(5)

    def stat_card(col, css_cls, label, value, sub=""):
        with col:
            st.markdown(f"""
            <div class="nb-stat-card {css_cls}">
              <div class="nb-stat-label">{label}</div>
              <div class="nb-stat-value {css_cls}">{value}</div>
              <div class="nb-stat-sub">{sub}</div>
            </div>""", unsafe_allow_html=True)

    stat_card(s1, "total",    "Total Findings",  summary["total_findings"],    f"Score: {summary['severity_score_total']}")
    stat_card(s2, "Critical", "Critical",         sc["Critical"],               "Score ×10")
    stat_card(s3, "High",     "High",             sc["High"],                   "Score ×7")
    stat_card(s4, "Medium",   "Medium",           sc["Medium"],                 "Score ×4")
    stat_card(s5, "Low",      "Low",              sc["Low"],                    "Score ×1")

    st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

    # ── Findings Chart & Filters ──
    chart_col, filter_col = st.columns([1, 1.5], gap="large")
    with chart_col:
        st.markdown('<div class="nb-findings-title" style="margin-bottom:-10px;">Severity Breakdown</div>', unsafe_allow_html=True)
        fig = go.Figure(data=[go.Pie(
            labels=SEV_ORDER,
            values=[sc[s] for s in SEV_ORDER],
            hole=0.6,
            marker=dict(colors=["#f85149", "#e3703b", "#e3b341", "#3fb950"], line=dict(color="#080b10", width=4)),
            textinfo="none",
            hoverinfo="label+value+percent"
        )])
        fig.add_annotation(text=f"<span style='font-size:32px; color:white; font-family:\"Syne\", sans-serif; font-weight:800;'>{summary['total_findings']}</span>", x=0.5, y=0.5, showarrow=False)
        fig.update_layout(
            height=200, 
            margin=dict(l=0, r=0, t=10, b=10), 
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=True,
            legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=0.8, font=dict(color="#8b949e", size=11, family="JetBrains Mono"))
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

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
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    # ── Apply filters ──
    filtered = [
        f for f in findings
        if f.get("severity", "Unknown") in sev_filter
        and f.get("cloud_provider", "unknown") in cloud_filter
        and f.get("category", "Uncategorized") in cat_filter
    ]
    # Sort: Critical first
    sev_rank = {s: i for i, s in enumerate(SEV_ORDER)}
    filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "Unknown"), 99))

    # ── Findings table ──
    st.markdown(f"""
    <div class="nb-findings-title" style="margin-top:8px;">
      Findings &nbsp;<span style="font-size:12px;color:#444c56;font-family:'JetBrains Mono'">
      {len(filtered)} of {len(findings)} shown
      </span>
    </div>""", unsafe_allow_html=True)

    CLOUD_ICONS = {"aws": "🟠", "azure": "🔵", "gcp": "🟢"}

    rows_html = ""
    for f in filtered:
        cloud = f.get("cloud_provider", "unknown")
        sev   = f.get("severity", "Unknown")
        status = f.get("status", "FAIL")
        cloud_icon = CLOUD_ICONS.get(cloud, "⚪")
        description = f.get("description", "")
        rows_html += f"""<tr>
  <td><span class="nb-pill {sev}">{sev}</span></td>
  <td><span class="nb-cloud-badge {cloud}">{cloud_icon} {cloud.upper()}</span></td>
  <td style="color:#c9d1d9;font-weight:500;">{f.get('rule_id', 'N/A')}</td>
  <td class="resource">{f.get('check', 'N/A')}</td>
  <td style="color:#58a6a6;font-size:11px;">{f.get('resource_type', 'N/A')}</td>
  <td style="color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{f.get('resource_id', 'N/A')}</td>
  <td style="color:#444c56;">{f.get('region','global')}</td>
  <td style="color:#6e7681;max-width:300px;font-size:11px;">{description[:80]}{'…' if len(description)>80 else ''}</td>
  <td><span class="nb-status-pill {status}">{status}</span></td>
</tr>"""

    st.markdown(f"""
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
""", unsafe_allow_html=True)

    # ── Footer ──
    st.markdown("""
    <div style="text-align:center;padding:32px 0 16px;color:#21262d;font-size:10px;letter-spacing:2px;text-transform:uppercase;">
      Nebuloupe · Multi-Cloud Security Scanner · Demo Mode
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# ROUTER
# ─────────────────────────────────────────────
if st.session_state.page == "landing":
    page_landing()
elif st.session_state.page == "dashboard":
    page_dashboard()