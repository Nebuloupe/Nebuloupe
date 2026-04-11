import importlib
import os
import json
import time
import uuid
from datetime import datetime
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1
}


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
    iac_rules_path = os.path.join(rules_base_path, 'iac', cloud_scope)
    common_rules_path = os.path.join(rules_base_path, 'iac', 'common')
    
    if not os.path.exists(iac_rules_path):
        print(f"   [!] No IaC rules directory found at: {iac_rules_path}")
        return full_report

    iac_plugins = []

    # Load cloud-specific IaC rules
    for root, dirs, files in os.walk(iac_rules_path):
        for f in files:
            if f.endswith('.py') and f != '__init__.py':
                rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                iac_plugins.append((cloud_scope, module_path))

    # Load cross-cloud common rules (db passwords, SSH keys, etc.)
    if os.path.exists(common_rules_path):
        for root, dirs, files in os.walk(common_rules_path):
            for f in files:
                if f.endswith('.py') and f != '__init__.py':
                    rel_path = os.path.relpath(os.path.join(root, f), rules_base_path)
                    module_path = os.path.splitext(rel_path)[0].replace(os.sep, '.')
                    iac_plugins.append((cloud_scope, module_path))

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
            for finding in findings:
                full_report["findings"].append(finding)
                
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


def start_scan(aws_session=None, azure_credential=None, gcp_project=None, cloud_scope="aws"):
    """
    Run live cloud API rules against actual cloud infrastructure.
    This requires valid cloud credentials.
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

    for provider, module_path, auth_context in plugins_to_run:
        rule_name = module_path.split('.')[-1]
        try:
            # 2. Dynamically import the rule module
            module = importlib.import_module(f"rules.{module_path}")
            print(f"   [+] Running {provider.upper()} check: {rule_name}...")
            
            # 3. Execute the standard run_check function
            findings = module.run_check(auth_context)
            
            # 4. Integrate flat findings
            for finding in findings:
                full_report["findings"].append(finding)
                
                # Update metrics
                severity = finding.get("severity", "Low")
                if severity in full_report["summary"]["severity_counts"]:
                    full_report["summary"]["severity_counts"][severity] += 1
                
                score = SEVERITY_SCORES.get(severity, 0)
                full_report["summary"]["severity_score_total"] += score
                
                # Only update the score for the cloud provider specified in the finding (or fallback)
                provider_key = finding.get("cloud_provider", provider).lower()
                if provider_key in full_report["summary"]["risk_score_by_cloud"]:
                    full_report["summary"]["risk_score_by_cloud"][provider_key] += score
                    
        except Exception as e:
            err_msg = f"Error running {provider} rule {rule_name}: {e}"
            print(f"   [!] {err_msg}")
            full_report["scan_metadata"]["errors"].append(err_msg)
            full_report["scan_metadata"]["status"] = "partial"

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