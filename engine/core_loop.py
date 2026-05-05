import importlib
import os
import json
import time
import uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}

SEVERITY_CANONICAL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# Maximum parallel workers for API rule execution
API_MAX_WORKERS = 10
ALLOWED_FINDING_STATUSES = {"PASS", "FAIL"}


def _normalize_finding(finding, default_provider=""):
    """Normalize finding fields so output format is consistent across rules."""
    if not isinstance(finding, dict):
        return None

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


def _is_allowed_finding_status(finding):
    """Return True only for PASS/FAIL findings that should be included in reports."""
    status = str(finding.get("status", "")).strip().upper()
    return status in ALLOWED_FINDING_STATUSES


def start_iac_scan(cloud_scope="aws", tf_path="."):
    """
    Run IaC (Infrastructure as Code) static analysis rules against Terraform files.
    
    This does NOT require cloud credentials — it scans .tf files from the given path.
    Rules are loaded from: rules/iac/{cloud_scope}/
    """
    print(f"[*] IaC Scanning Terraform files (Scope: {cloud_scope.upper()})...")
    scan_id = f"nl-iac-{uuid.uuid4().hex[:8]}"
    start_time = time.time()
    start_time_iso = datetime.now().isoformat()

    # Validate tf_path exists
    tf_path = os.path.abspath(tf_path)
    if not os.path.exists(tf_path):
        print(f"   [!] Terraform path does not exist: {tf_path}")
        return None

    # Count .tf files
    tf_file_count = 0
    for root, dirs, files in os.walk(tf_path):
        for f in files:
            if f.endswith('.tf') or f.endswith('.tf.json'):
                tf_file_count += 1
    
    print(f"   [*] Found {tf_file_count} Terraform file(s) in: {tf_path}")
    
    if tf_file_count == 0:
        print(f"   [!] No Terraform files found in {tf_path}")

    # Initialize the report schema
    full_report = {
        "scan_metadata": {
            "scan_id": scan_id,
            "scan_started_at": start_time_iso,
            "scan_completed_at": "",
            "scan_duration_seconds": 0,
            "cloud_scope": cloud_scope,
            "scan_mode": "iac",
            "target_account": f"terraform:{tf_path}",
            "terraform_path": tf_path,
            "terraform_files_count": tf_file_count,
            "status": "success",
            "errors": []
        },
        "summary": {
            "total_findings": 0,
            "severity_counts": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            },
            "severity_score_total": 0,
            "risk_score_by_cloud": {
                "aws": 0,
                "azure": 0,
                "gcp": 0
            }
        },
        "findings": []
    }

    # Discover IaC rules from rules/iac/{cloud_scope}/ and rules/iac/common/
    rules_base_path = 'rules'
    selected_scopes = [cloud_scope]
    if cloud_scope == "all":
        selected_scopes = ["aws", "azure", "gcp"]

    common_rules_path = os.path.join(rules_base_path, 'iac', 'common')

    iac_plugins = []
    seen_modules = set()

    # Load cloud-specific IaC rules
    found_scope_rules = False
    for scope in selected_scopes:
        iac_rules_path = os.path.join(rules_base_path, 'iac', scope)
        if not os.path.exists(iac_rules_path):
            continue
        found_scope_rules = True
        for root, dirs, files in os.walk(iac_rules_path):
            for f in files:
                if f.endswith('.py') and f != '__init__.py':
                    rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                    module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                    if module_path not in seen_modules:
                        iac_plugins.append((scope, module_path))
                        seen_modules.add(module_path)

    if not found_scope_rules:
        print(f"   [!] No IaC rules directory found for scope: {cloud_scope}")
        return full_report

    # Load cross-cloud common rules (db passwords, SSH keys, etc.)
    if os.path.exists(common_rules_path):
        for root, dirs, files in os.walk(common_rules_path):
            for f in files:
                if f.endswith('.py') and f != '__init__.py':
                    rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                    module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                    if module_path not in seen_modules:
                        iac_plugins.append((cloud_scope, module_path))
                        seen_modules.add(module_path)

    print(f"   [*] Loaded {len(iac_plugins)} IaC rule(s) for {cloud_scope.upper()} (incl. common)")
    print()

    # Execute each IaC rule
    for provider, module_path in iac_plugins:
        rule_name = module_path.split('.')[-1]
        try:
            module = importlib.import_module(f"rules.{module_path}")
            print(f"   [+] Running IaC check: {rule_name}...")
            
            # IaC rules accept (session, tf_path) — session is None for IaC
            findings = module.run_check(None, tf_path=tf_path)
            
            # Integrate findings into report
            for raw_finding in findings:
                finding = _normalize_finding(raw_finding, provider)
                if not finding:
                    continue
                if not _is_allowed_finding_status(finding):
                    continue

                full_report["findings"].append(finding)

                # Score only failing findings.
                if str(finding.get("status", "")).upper() != "FAIL":
                    continue
                
                severity = finding.get("severity", "Low")
                if severity in full_report["summary"]["severity_counts"]:
                    full_report["summary"]["severity_counts"][severity] += 1
                
                score = SEVERITY_SCORES.get(severity, 0)
                full_report["summary"]["severity_score_total"] += score
                
                provider_key = finding.get("cloud_provider", provider).lower()
                if provider_key in full_report["summary"]["risk_score_by_cloud"]:
                    full_report["summary"]["risk_score_by_cloud"][provider_key] += score

        except Exception as e:
            err_msg = f"Error running IaC rule {rule_name}: {e}"
            print(f"   [!] {err_msg}")
            full_report["scan_metadata"]["errors"].append(err_msg)
            full_report["scan_metadata"]["status"] = "partial"

    # Finalize
    end_time = time.time()
    full_report["scan_metadata"]["scan_completed_at"] = datetime.now().isoformat()
    full_report["scan_metadata"]["scan_duration_seconds"] = round(end_time - start_time, 2)
    full_report["summary"]["total_findings"] = len(full_report["findings"])

    # Save IaC results
    output_file = os.path.join('output', 'results.json')
    os.makedirs('output', exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(full_report, f, indent=4)
    
    fail_count = sum(1 for f in full_report["findings"] if f.get("status") == "FAIL")
    pass_count = sum(1 for f in full_report["findings"] if f.get("status") == "PASS")
    
    print(f"\n[+] IaC Scan Complete! {pass_count} PASS, {fail_count} FAIL across "
          f"{full_report['summary']['total_findings']} finding(s). Results saved to {output_file}")
    
    return full_report


def _run_single_api_rule(provider, module_path, auth_context):
    """Execute a single API rule. Designed to be called from a thread pool."""
    rule_name = module_path.split('.')[-1]
    try:
        module = importlib.import_module(f"rules.{module_path}")
        print(f"   [+] Running {provider.upper()} check: {rule_name}...")
        
        findings = module.run_check(auth_context)
        
        return {
            "provider": provider,
            "rule_name": rule_name,
            "findings": findings,
            "error": None
        }
    except Exception as e:
        err_msg = f"Error running {provider} rule {rule_name}: {e}"
        print(f"   [!] {err_msg}")
        return {
            "provider": provider,
            "rule_name": rule_name,
            "findings": [],
            "error": err_msg
        }


def start_scan(aws_session=None, azure_credential=None, gcp_project=None, cloud_scope="aws"):
    """
    Run live cloud API rules against actual cloud infrastructure.
    This requires valid cloud credentials.
    
    Uses ThreadPoolExecutor for parallel rule execution — each rule makes
    independent API calls, so running them concurrently reduces total scan
    time by overlapping network I/O wait times.
    """
    print(f"[*] Scanning Infrastructure (Scope: {cloud_scope.upper()})...")     
    scan_id = f"nl-scan-{uuid.uuid4().hex[:8]}"
    start_time = time.time()
    start_time_iso = datetime.now().isoformat()

    target_account = "Multiple"
    if cloud_scope == "aws" and aws_session:
        try:
            target_account = aws_session.client('sts').get_caller_identity().get('Account', 'Unknown AWS')
        except Exception as e:
            print(f"Failed to get AWS account ID: {e}")
    elif cloud_scope == "gcp" and gcp_project:
        target_account = gcp_project

    # Initialize the required schema
    full_report = {
        "scan_metadata": {
            "scan_id": scan_id,
            "scan_started_at": start_time_iso,
            "scan_completed_at": "",
            "scan_duration_seconds": 0,
            "cloud_scope": cloud_scope,
            "scan_mode": "api",
            "target_account": target_account,
            "status": "success",
            "errors": []
        },
        "summary": {
            "total_findings": 0,
            "severity_counts": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0
            },
            "severity_score_total": 0,
            "risk_score_by_cloud": {
                "aws": 0,
                "azure": 0,
                "gcp": 0
            }
        },
        "findings": []
    }

    # Build a list of plugins to execute based on the selected scope
    plugins_to_run = []
    
    rules_base_path = 'rules'

    if cloud_scope in ["aws", "all"] and aws_session:
        aws_rules_path = os.path.join(rules_base_path, 'aws')
        if os.path.exists(aws_rules_path):
            # Recursively find all rules
            for root, dirs, files in os.walk(aws_rules_path):
                for f in files:
                    if f.endswith('.py') and f != '__init__.py':
                        # Convert file path to module path (e.g. aws.storage.rule)
                        rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                        module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                        plugins_to_run.append(("aws", module_path, aws_session))

    if cloud_scope in ["azure", "all"] and azure_credential:
        azure_rules_path = os.path.join(rules_base_path, 'azure')
        if os.path.exists(azure_rules_path):
            # Recursively find all rules
            for root, dirs, files in os.walk(azure_rules_path):
                for f in files:
                    if f.endswith('.py') and f != '__init__.py':
                        rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                        module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                        plugins_to_run.append(("azure", module_path, azure_credential))
                        
    if cloud_scope in ["gcp", "all"] and gcp_project:
        gcp_rules_path = os.path.join(rules_base_path, 'gcp')
        if os.path.exists(gcp_rules_path):
            # Recursively find all rules
            for root, dirs, files in os.walk(gcp_rules_path):
                for f in files:
                    if f.endswith('.py') and f != '__init__.py':
                        rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                        module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                        plugins_to_run.append(("gcp", module_path, gcp_project))
    
    # ── Execute API rules in PARALLEL using ThreadPoolExecutor ──
    # Each rule makes independent cloud API calls (network I/O bound),
    # so running them concurrently overlaps wait times for ~3-8x speedup.
    num_workers = min(API_MAX_WORKERS, len(plugins_to_run)) if plugins_to_run else 1
    
    print(f"   [*] Executing {len(plugins_to_run)} rule(s) with {num_workers} parallel workers...")
    
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = {
            executor.submit(
                _run_single_api_rule, provider, module_path, auth_context
            ): (provider, module_path)
            for provider, module_path, auth_context in plugins_to_run
        }
        
        for future in as_completed(futures):
            result = future.result()
            
            if result["error"]:
                full_report["scan_metadata"]["errors"].append(result["error"])
                full_report["scan_metadata"]["status"] = "partial"
            
            for raw_finding in result["findings"]:
                finding = _normalize_finding(raw_finding, result["provider"])
                if not finding:
                    continue
                if not _is_allowed_finding_status(finding):
                    continue

                full_report["findings"].append(finding)

                # Score only failing findings.
                if str(finding.get("status", "")).upper() != "FAIL":
                    continue
                
                # Update metrics
                severity = finding.get("severity", "Low")
                if severity in full_report["summary"]["severity_counts"]:
                    full_report["summary"]["severity_counts"][severity] += 1
                
                score = SEVERITY_SCORES.get(severity, 0)
                full_report["summary"]["severity_score_total"] += score
                
                # Only update the score for the cloud provider specified in the finding (or fallback)
                provider_key = finding.get("cloud_provider", result["provider"]).lower()
                if provider_key in full_report["summary"]["risk_score_by_cloud"]:
                    full_report["summary"]["risk_score_by_cloud"][provider_key] += score

    # Finalize timestamps and durations
    end_time = time.time()
    full_report["scan_metadata"]["scan_completed_at"] = datetime.now().isoformat()
    # Round duration
    full_report["scan_metadata"]["scan_duration_seconds"] = round(end_time - start_time, 2)
    full_report["summary"]["total_findings"] = len(full_report["findings"])

    if full_report["scan_metadata"]["status"] != "partial" and len(full_report["scan_metadata"]["errors"]) > 0:
        full_report["scan_metadata"]["status"] = "partial"

    # 5. Save results to the output folder
    output_file = os.path.join('output', 'results.json')
    os.makedirs('output', exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(full_report, f, indent=4)
        
    print(f"\n[+] Scan Complete! Found {full_report['summary']['total_findings']} issue(s). Results saved to {output_file}")
    return full_report