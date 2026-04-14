from engine.auth import AuthError, get_aws_session, get_azure_credentials, get_gcp_project
from engine.core_loop import start_scan, start_iac_scan
import logging

logging.basicConfig(level=logging.INFO, format="%(message)s")

def run_scanner(cloud_scope, mode="api", tf_path=None, fail_on_severities=None):
    """
    Main entry point for running scans.
    
    Modes:
      - "api": Run live cloud API rules only (requires credentials)
      - "iac": Run Terraform static analysis rules only (requires tf_path)
      - "all": Run IaC scan first, gate on results, then run API scan
    """
    logging.info(f"[*] Starting Nebuloupe scan for scope: {cloud_scope}")
    
    iac_report = None
    api_report = None
    
    # ─────────────────────────────────────────
    # STEP 1: IaC SCAN (if mode is 'iac' or 'all')
    # ─────────────────────────────────────────
    if mode in ["iac", "all"] and tf_path:
        logging.info(f"\n{'='*50}")
        logging.info(f"  PHASE 1: IaC Static Analysis")
        logging.info(f"  Scanning Terraform files in: {tf_path}")
        logging.info(f"{'='*50}\n")
        
        iac_report = start_iac_scan(
            cloud_scope=cloud_scope,
            tf_path=tf_path
        )
        
        if iac_report:
            # Summarize IaC findings
            iac_findings = iac_report.get("findings", [])
            iac_fails = [f for f in iac_findings if f.get("status") == "FAIL"]
            critical_high = [f for f in iac_fails if f.get("severity") in ["Critical", "High"]]
            
            logging.info(f"\n[*] IaC Scan Summary:")
            logging.info(f"    Total findings : {len(iac_findings)}")
            logging.info(f"    FAIL           : {len(iac_fails)}")
            logging.info(f"    Critical/High  : {len(critical_high)}")
            
            # If mode is 'all', gate on critical/high IaC findings before proceeding to API
            if mode == "all" and critical_high:
                logging.warning(f"\n[!] IaC GATE: {len(critical_high)} Critical/High misconfiguration(s) detected in Terraform.")
                logging.warning(f"    Fix these issues before deploying infrastructure.")
                for f in critical_high[:10]:
                    logging.warning(f"    • [{f.get('severity')}] {f.get('check')}: {f.get('resource_id')}")
                logging.warning(f"\n[!] Skipping API scan due to IaC failures. Fix Terraform first.")
                
                # Still save the IaC results
                return iac_report
            
            if mode == "all":
                logging.info(f"\n[✓] IaC scan passed — no Critical/High issues. Proceeding to API scan...\n")
        
        # If IaC-only mode, return the IaC report
        if mode == "iac":
            return iac_report
    
    # ─────────────────────────────────────────
    # STEP 2: API SCAN (if mode is 'api' or 'all')
    # ─────────────────────────────────────────
    if mode in ["api", "all"]:
        logging.info(f"\n{'='*50}")
        logging.info(f"  {'PHASE 2: ' if mode == 'all' else ''}Live Cloud API Scan")
        logging.info(f"{'='*50}\n")
        
        aws_session = None
        azure_credential = None
        gcp_project = None

        if cloud_scope == "aws":
            try:
                aws_session = get_aws_session()
            except AuthError as e:
                logging.error(str(e))
            if not aws_session:
                logging.warning("Could not obtain AWS session.")

        if cloud_scope == "azure":
            try:
                azure_credential = get_azure_credentials()
            except AuthError as e:
                logging.error(str(e))
            if not azure_credential:
                logging.warning("Could not obtain Azure credentials.")
                
        if cloud_scope == "gcp":
            try:
                gcp_project = get_gcp_project()
            except AuthError as e:
                logging.error(str(e))
            if not gcp_project:
                logging.warning("Could not obtain GCP Project ID.")

        if aws_session or azure_credential or gcp_project:
            api_report = start_scan(
                aws_session=aws_session,
                azure_credential=azure_credential,
                gcp_project=gcp_project,
                cloud_scope=cloud_scope
            )
        else:
            logging.error("[-] No valid credentials found for the requested cloud scope.")
            # If we have IaC results, return those at least
            if iac_report:
                logging.info("[*] Returning IaC scan results only.")
                return iac_report
            return None
    
    # ─────────────────────────────────────────
    # STEP 3: MERGE REPORTS (if both IaC and API ran)
    # ─────────────────────────────────────────
    if iac_report and api_report:
        return _merge_reports(iac_report, api_report)
    elif api_report:
        return api_report
    elif iac_report:
        return iac_report
    else:
        return None


def _merge_reports(iac_report, api_report):
    """Merge IaC and API scan reports into a single unified report."""
    merged = api_report.copy()
    
    # Merge findings
    merged["findings"] = iac_report.get("findings", []) + api_report.get("findings", [])
    
    # Recalculate summary
    severity_scores = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    risk_by_cloud = {"aws": 0, "azure": 0, "gcp": 0}
    total_score = 0
    
    for f in merged["findings"]:
        if str(f.get("status", "")).upper() != "FAIL":
            continue

        sev = f.get("severity", "Low")
        if sev in severity_counts:
            severity_counts[sev] += 1
        score = severity_scores.get(sev, 0)
        total_score += score
        provider = f.get("cloud_provider", "aws").lower()
        if provider in risk_by_cloud:
            risk_by_cloud[provider] += score
    
    merged["summary"] = {
        "total_findings": len(merged["findings"]),
        "severity_counts": severity_counts,
        "severity_score_total": total_score,
        "risk_score_by_cloud": risk_by_cloud
    }
    
    # Update metadata
    merged["scan_metadata"]["cloud_scope"] = api_report["scan_metadata"]["cloud_scope"]
    merged["scan_metadata"]["scan_mode"] = "iac+api"
    
    logging.info(f"\n[*] Merged Report: {len(iac_report.get('findings', []))} IaC + "
                 f"{len(api_report.get('findings', []))} API = "
                 f"{len(merged['findings'])} total findings")
    
    return merged