import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure Storage Accounts in Terraform with
    public blob access enabled (allow_blob_public_access = true or
    public_network_access_enabled = true).
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-STOR-01", "Terraform Azure Storage Public Access", "Info",
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
        # Check allow_blob_public_access (deprecated but still common)
        blob_public = re.search(r'allow_blob_public_access\s*=\s*(true|false)', body, re.IGNORECASE)
        # Check allow_nested_items_to_be_public (newer API)
        nested_public = re.search(r'allow_nested_items_to_be_public\s*=\s*(true|false)', body, re.IGNORECASE)
        # Check public_network_access_enabled
        network_public = re.search(r'public_network_access_enabled\s*=\s*(true|false)', body, re.IGNORECASE)

        is_public = False
        if blob_public and blob_public.group(1).lower() == "true":
            is_public = True
        if nested_public and nested_public.group(1).lower() == "true":
            is_public = True
        if network_public and network_public.group(1).lower() == "true":
            is_public = True

        if is_public:
            findings.append(create_finding(
                "IAC-AZ-STOR-01", "Terraform Azure Storage Public Access", "High",
                "FAIL", f"azurerm_storage_account.{name}",
                f"Storage account '{name}' has public access enabled. "
                "Blobs or containers may be exposed to the internet.",
                "Set allow_nested_items_to_be_public = false and "
                "public_network_access_enabled = false.",
                {"storage_account": name, "public_access": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-STOR-01", "Terraform Azure Storage Public Access", "Low",
                "PASS", f"azurerm_storage_account.{name}",
                f"Storage account '{name}' does not have public access enabled.",
                "No action required.",
                {"storage_account": name, "public_access": False}
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
        "category": "IaC Storage",
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
