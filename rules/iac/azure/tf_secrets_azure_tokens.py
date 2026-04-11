import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect hardcoded Azure credentials in Terraform files.
    Looks for client_id, client_secret, tenant_id, and subscription_id.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-SEC-01", "Terraform Azure Hardcoded Tokens", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    # Patterns for Azure credentials
    patterns = [
        (re.compile(r'client_secret\s*=\s*"([^"]{8,})"', re.IGNORECASE), "Azure Client Secret"),
        (re.compile(r'client_id\s*=\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.IGNORECASE), "Azure Client ID"),
        (re.compile(r'tenant_id\s*=\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.IGNORECASE), "Azure Tenant ID"),
        (re.compile(r'subscription_id\s*=\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.IGNORECASE), "Azure Subscription ID"),
    ]

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception:
            continue

        file_has_secret = False
        for line_num, line in enumerate(lines, start=1):
            for pattern, label in patterns:
                if pattern.search(line):
                    file_has_secret = True
                    severity = "Critical" if "secret" in label.lower() else "High"
                    findings.append(create_finding(
                        "IAC-AZ-SEC-01", f"Terraform {label} Hardcoded", severity,
                        "FAIL", tf_file,
                        f"Hardcoded {label} found at line {line_num} in {os.path.basename(tf_file)}. "
                        "Credentials in source code risk exposure via version control.",
                        "Use environment variables, Azure Managed Identity, or a secrets manager "
                        "(e.g., Azure Key Vault, HashiCorp Vault) instead.",
                        {"file": tf_file, "line": line_num, "pattern": label}
                    ))

        if not file_has_secret:
            findings.append(create_finding(
                "IAC-AZ-SEC-01", "Terraform Azure Hardcoded Tokens", "Low",
                "PASS", tf_file,
                f"No hardcoded Azure credentials detected in {os.path.basename(tf_file)}.",
                "No action required.",
                {"file": tf_file, "status": "clean"}
            ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "azure",
        "category": "IaC Secrets",
        "resource_type": "terraform_file",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs#authenticating-to-azure"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
