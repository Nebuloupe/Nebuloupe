import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect GCP projects or compute instances where
    OS Login is not enabled. OS Login provides centralized SSH key management
    tied to IAM and replaces legacy SSH key metadata.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-OS-01", "Terraform GCP OS Login", "Info",
            "PASS", "N/A", "No Terraform files found.", "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    all_content = ""
    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                all_content += f"\n# FILE: {tf_file}\n" + f.read()
        except Exception:
            continue

    # Check google_compute_project_metadata for enable-oslogin
    project_meta_pattern = re.compile(
        r'resource\s+"google_compute_project_metadata"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in project_meta_pattern.findall(all_content):
        metadata = re.search(r'metadata\s*=\s*\{(.*?)\}', body, re.DOTALL)
        if metadata:
            os_login = re.search(r'enable-oslogin\s*=\s*"?(true|false|TRUE|FALSE)"?',
                                 metadata.group(1), re.IGNORECASE)
            if not os_login or os_login.group(1).lower() == "false":
                findings.append(create_finding(
                    "IAC-GCP-OS-01", "Terraform GCP Project OS Login Disabled", "Medium",
                    "FAIL", f"google_compute_project_metadata.{name}",
                    f"Project metadata '{name}' does not have enable-oslogin = true. "
                    "Without OS Login, SSH keys are managed via instance metadata, "
                    "bypassing IAM controls.",
                    "Set enable-oslogin = 'TRUE' in project metadata.",
                    {"resource": name, "os_login": False}
                ))
            else:
                findings.append(create_finding(
                    "IAC-GCP-OS-01", "Terraform GCP Project OS Login", "Low",
                    "PASS", f"google_compute_project_metadata.{name}",
                    f"Project metadata '{name}' has OS Login enabled.",
                    "No action required.",
                    {"resource": name, "os_login": True}
                ))

    # Check individual compute instances for OS Login override
    instance_pattern = re.compile(
        r'resource\s+"google_compute_instance"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for inst_name, inst_body in instance_pattern.findall(all_content):
        metadata = re.search(r'metadata\s*=\s*\{(.*?)\}', inst_body, re.DOTALL)
        if metadata:
            os_login = re.search(r'enable-oslogin\s*=\s*"?(true|false|TRUE|FALSE)"?',
                                 metadata.group(1), re.IGNORECASE)
            if os_login and os_login.group(1).lower() == "false":
                findings.append(create_finding(
                    "IAC-GCP-OS-01", "Terraform GCP Instance OS Login Disabled", "Medium",
                    "FAIL", f"google_compute_instance.{inst_name}",
                    f"Compute instance '{inst_name}' explicitly disables OS Login. "
                    "SSH access is managed via legacy metadata keys instead of IAM.",
                    "Remove enable-oslogin = false or set it to true.",
                    {"instance": inst_name, "os_login": False}
                ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "IaC IAM",
        "resource_type": "google_compute_project_metadata",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/compute/docs/instances/managing-instance-access",
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_project_metadata"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
