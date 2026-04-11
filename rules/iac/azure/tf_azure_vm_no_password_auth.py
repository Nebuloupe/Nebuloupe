import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure Linux VMs using password authentication
    instead of SSH key authentication.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-VM-01", "Terraform Azure VM Password Auth", "Info",
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

    # Check azurerm_linux_virtual_machine
    vm_pattern = re.compile(
        r'resource\s+"azurerm_linux_virtual_machine"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for vm_name, vm_body in vm_pattern.findall(all_content):
        disable_pw = re.search(
            r'disable_password_authentication\s*=\s*(true|false)', vm_body, re.IGNORECASE
        )
        admin_password = re.search(r'admin_password\s*=\s*"', vm_body)

        if disable_pw and disable_pw.group(1).lower() == "false":
            findings.append(create_finding(
                "IAC-AZ-VM-01", "Terraform Azure VM Password Auth", "High",
                "FAIL", f"azurerm_linux_virtual_machine.{vm_name}",
                f"Linux VM '{vm_name}' has disable_password_authentication = false. "
                "Password authentication is weaker than SSH key-based authentication "
                "and susceptible to brute-force attacks.",
                "Set disable_password_authentication = true and configure admin_ssh_key block.",
                {"vm": vm_name, "password_auth": True}
            ))
        elif admin_password and not disable_pw:
            findings.append(create_finding(
                "IAC-AZ-VM-01", "Terraform Azure VM Password Auth", "High",
                "FAIL", f"azurerm_linux_virtual_machine.{vm_name}",
                f"Linux VM '{vm_name}' has admin_password set without explicitly disabling "
                "password authentication.",
                "Set disable_password_authentication = true and use SSH keys.",
                {"vm": vm_name, "password_auth": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-VM-01", "Terraform Azure VM Password Auth", "Low",
                "PASS", f"azurerm_linux_virtual_machine.{vm_name}",
                f"Linux VM '{vm_name}' has password authentication disabled.",
                "No action required.",
                {"vm": vm_name, "password_auth": False}
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
        "category": "IaC Compute",
        "resource_type": "azurerm_linux_virtual_machine",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
