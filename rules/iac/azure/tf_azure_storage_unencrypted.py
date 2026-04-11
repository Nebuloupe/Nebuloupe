import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure Storage Accounts without
    infrastructure encryption or HTTPS-only traffic enforcement.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-STOR-02", "Terraform Azure Storage Encryption", "Info",
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

    storage_pattern = re.compile(
        r'resource\s+"azurerm_storage_account"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in storage_pattern.findall(all_content):
        issues = []

        # Check enable_https_traffic_only (should be true)
        https_only = re.search(r'enable_https_traffic_only\s*=\s*(true|false)', body, re.IGNORECASE)
        if https_only and https_only.group(1).lower() == "false":
            issues.append("HTTPS-only traffic is disabled")

        # Check infrastructure_encryption_enabled
        infra_enc = re.search(r'infrastructure_encryption_enabled\s*=\s*(true|false)', body, re.IGNORECASE)
        if not infra_enc or infra_enc.group(1).lower() == "false":
            issues.append("Infrastructure encryption is not enabled")

        # Check min_tls_version
        tls_version = re.search(r'min_tls_version\s*=\s*"(TLS1_[012])"', body)
        if tls_version and tls_version.group(1) in ["TLS1_0", "TLS1_1"]:
            issues.append(f"Minimum TLS version is {tls_version.group(1)} (should be TLS1_2)")

        if issues:
            findings.append(create_finding(
                "IAC-AZ-STOR-02", "Terraform Azure Storage Encryption", "Medium",
                "FAIL", f"azurerm_storage_account.{name}",
                f"Storage account '{name}' has encryption issues: {'; '.join(issues)}.",
                "Enable infrastructure_encryption_enabled = true, "
                "enable_https_traffic_only = true, and min_tls_version = 'TLS1_2'.",
                {"storage_account": name, "issues": issues}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-STOR-02", "Terraform Azure Storage Encryption", "Low",
                "PASS", f"azurerm_storage_account.{name}",
                f"Storage account '{name}' has proper encryption configuration.",
                "No action required.",
                {"storage_account": name, "encryption": "configured"}
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
        "category": "IaC Encryption",
        "resource_type": "azurerm_storage_account",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
