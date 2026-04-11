import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Azure SQL Servers with public network access enabled
    or firewall rules allowing 0.0.0.0/0.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AZ-SQL-01", "Terraform Azure SQL Public Access", "Info",
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

    # Check azurerm_mssql_server
    sql_pattern = re.compile(
        r'resource\s+"azurerm_mssql_server"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in sql_pattern.findall(all_content):
        public_access = re.search(
            r'public_network_access_enabled\s*=\s*(true|false)', body, re.IGNORECASE
        )

        if public_access and public_access.group(1).lower() == "true":
            findings.append(create_finding(
                "IAC-AZ-SQL-01", "Terraform Azure SQL Public Access", "Critical",
                "FAIL", f"azurerm_mssql_server.{name}",
                f"SQL Server '{name}' has public_network_access_enabled = true. "
                "The database server is accessible from the public internet.",
                "Set public_network_access_enabled = false and use Private Endpoints.",
                {"sql_server": name, "public_access": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AZ-SQL-01", "Terraform Azure SQL Public Access", "Low",
                "PASS", f"azurerm_mssql_server.{name}",
                f"SQL Server '{name}' does not have public network access enabled.",
                "No action required.",
                {"sql_server": name, "public_access": False}
            ))

    # Check azurerm_sql_firewall_rule for 0.0.0.0 (Allow Azure Services)
    fw_pattern = re.compile(
        r'resource\s+"azurerm_mssql_firewall_rule"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for rule_name, rule_body in fw_pattern.findall(all_content):
        start_ip = re.search(r'start_ip_address\s*=\s*"([^"]+)"', rule_body)
        end_ip = re.search(r'end_ip_address\s*=\s*"([^"]+)"', rule_body)

        if start_ip and end_ip:
            if (start_ip.group(1) == "0.0.0.0" and end_ip.group(1) == "255.255.255.255"):
                findings.append(create_finding(
                    "IAC-AZ-SQL-01", "Terraform Azure SQL Firewall Wide Open", "Critical",
                    "FAIL", f"azurerm_mssql_firewall_rule.{rule_name}",
                    f"SQL firewall rule '{rule_name}' allows access from ALL IP addresses "
                    "(0.0.0.0 to 255.255.255.255).",
                    "Restrict IP range to specific trusted addresses only.",
                    {"rule": rule_name, "start_ip": "0.0.0.0", "end_ip": "255.255.255.255"}
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
        "category": "IaC Database",
        "resource_type": "azurerm_mssql_server",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
