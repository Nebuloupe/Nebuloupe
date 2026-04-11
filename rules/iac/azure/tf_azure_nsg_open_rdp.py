import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure NSG rules allowing inbound RDP (port 3389)
    from 0.0.0.0/0 or * (any source).
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-NSG-02", "Terraform Azure NSG Open RDP", "Info",
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

    nsg_pattern = re.compile(
        r'resource\s+"azurerm_network_security_group"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for nsg_name, nsg_body in nsg_pattern.findall(all_content):
        rules = re.findall(r'security_rule\s*\{(.*?)\}', nsg_body, re.DOTALL)
        open_rdp = False

        for rule in rules:
            direction = re.search(r'direction\s*=\s*"(\w+)"', rule, re.IGNORECASE)
            access = re.search(r'access\s*=\s*"(\w+)"', rule, re.IGNORECASE)
            dest_port = re.search(r'destination_port_range\s*=\s*"([^"]+)"', rule)
            source_addr = re.search(r'source_address_prefix\s*=\s*"([^"]+)"', rule)

            if (direction and direction.group(1).lower() == "inbound" and
                access and access.group(1).lower() == "allow"):
                port_val = dest_port.group(1) if dest_port else ""
                source_val = source_addr.group(1) if source_addr else ""

                if (port_val in ["3389", "*"] and source_val in ["*", "0.0.0.0/0", "Internet"]):
                    open_rdp = True

        if open_rdp:
            findings.append(create_finding(
                "IAC-AZ-NSG-02", "Terraform Azure NSG Open RDP", "Critical",
                "FAIL", f"azurerm_network_security_group.{nsg_name}",
                f"NSG '{nsg_name}' allows inbound RDP (port 3389) from any source. "
                "This exposes Windows VMs to brute-force and remote exploitation.",
                "Restrict source_address_prefix to specific trusted IP ranges. "
                "Use Azure Bastion for secure remote desktop access.",
                {"nsg": nsg_name, "port": 3389, "source": "*"}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-NSG-02", "Terraform Azure NSG Open RDP", "Low",
                "PASS", f"azurerm_network_security_group.{nsg_name}",
                f"NSG '{nsg_name}' does not allow unrestricted RDP from the internet.",
                "No action required.",
                {"nsg": nsg_name, "rdp_open": False}
            ))

    # Check standalone NSG rules
    nsr_pattern = re.compile(
        r'resource\s+"azurerm_network_security_rule"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for rule_name, rule_body in nsr_pattern.findall(all_content):
        direction = re.search(r'direction\s*=\s*"(\w+)"', rule_body, re.IGNORECASE)
        access = re.search(r'access\s*=\s*"(\w+)"', rule_body, re.IGNORECASE)
        dest_port = re.search(r'destination_port_range\s*=\s*"([^"]+)"', rule_body)
        source_addr = re.search(r'source_address_prefix\s*=\s*"([^"]+)"', rule_body)

        if (direction and direction.group(1).lower() == "inbound" and
            access and access.group(1).lower() == "allow"):
            port_val = dest_port.group(1) if dest_port else ""
            source_val = source_addr.group(1) if source_addr else ""

            if (port_val in ["3389", "*"] and source_val in ["*", "0.0.0.0/0", "Internet"]):
                findings.append(create_finding(
                    "IAC-AZ-NSG-02", "Terraform Azure NSG Rule Open RDP", "Critical",
                    "FAIL", f"azurerm_network_security_rule.{rule_name}",
                    f"NSG rule '{rule_name}' allows inbound RDP from any source.",
                    "Restrict source_address_prefix to trusted IP ranges.",
                    {"rule": rule_name, "port": 3389, "source": source_val}
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
        "category": "IaC Networking",
        "resource_type": "azurerm_network_security_group",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_group"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
