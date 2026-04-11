import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure Key Vaults without purge protection enabled.
    Without purge protection, deleted vaults/secrets can be permanently lost.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-KV-01", "Terraform Azure Key Vault Purge Protection", "Info",
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

    kv_pattern = re.compile(
        r'resource\s+"azurerm_key_vault"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for kv_name, kv_body in kv_pattern.findall(all_content):
        purge_protection = re.search(
            r'purge_protection_enabled\s*=\s*(true|false)', kv_body, re.IGNORECASE
        )
        soft_delete = re.search(
            r'soft_delete_retention_days\s*=\s*(\d+)', kv_body
        )

        issues = []
        if not purge_protection or purge_protection.group(1).lower() == "false":
            issues.append("Purge protection is not enabled")
        if soft_delete and int(soft_delete.group(1)) < 7:
            issues.append(f"Soft delete retention is only {soft_delete.group(1)} days")

        if issues:
            findings.append(create_finding(
                "IAC-AZ-KV-01", "Terraform Azure Key Vault Purge Protection", "Medium",
                "FAIL", f"azurerm_key_vault.{kv_name}",
                f"Key Vault '{kv_name}' has issues: {'; '.join(issues)}. "
                "Without purge protection, deleted secrets/keys/certificates "
                "cannot be recovered and are permanently lost.",
                "Set purge_protection_enabled = true and soft_delete_retention_days >= 7.",
                {"key_vault": kv_name, "issues": issues}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-KV-01", "Terraform Azure Key Vault Purge Protection", "Low",
                "PASS", f"azurerm_key_vault.{kv_name}",
                f"Key Vault '{kv_name}' has purge protection properly configured.",
                "No action required.",
                {"key_vault": kv_name, "purge_protection": True}
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
        "category": "IaC Data Protection",
        "resource_type": "azurerm_key_vault",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
