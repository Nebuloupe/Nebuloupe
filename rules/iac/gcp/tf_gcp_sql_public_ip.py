import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect Cloud SQL instances with public IP
    and 0.0.0.0/0 authorized networks.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-SQL-01", "Terraform GCP SQL Public IP", "Info",
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

    sql_pattern = re.compile(
        r'resource\s+"google_sql_database_instance"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in sql_pattern.findall(all_content):
        # Check if ipv4_enabled = true (assigns public IP)
        ipv4_enabled = re.search(r'ipv4_enabled\s*=\s*(true|false)', body, re.IGNORECASE)
        
        # Check authorized_networks for 0.0.0.0/0
        auth_networks = re.findall(r'authorized_networks\s*\{(.*?)\}', body, re.DOTALL)
        has_open_network = False
        for network in auth_networks:
            value = re.search(r'value\s*=\s*"([^"]+)"', network)
            if value and value.group(1) in ["0.0.0.0/0", "0.0.0.0"]:
                has_open_network = True

        if ipv4_enabled and ipv4_enabled.group(1).lower() == "true" and has_open_network:
            findings.append(create_finding(
                "IAC-GCP-SQL-01", "Terraform GCP SQL Public IP + Open Network", "Critical",
                "FAIL", f"google_sql_database_instance.{name}",
                f"Cloud SQL instance '{name}' has a public IP (ipv4_enabled=true) with "
                "authorized_networks allowing 0.0.0.0/0. The database is fully exposed to the internet.",
                "Set ipv4_enabled = false and use Private IP. If public IP is required, "
                "restrict authorized_networks to specific CIDR ranges.",
                {"instance": name, "ipv4_enabled": True, "open_network": True}
            ))
        elif ipv4_enabled and ipv4_enabled.group(1).lower() == "true":
            findings.append(create_finding(
                "IAC-GCP-SQL-01", "Terraform GCP SQL Public IP", "High",
                "FAIL", f"google_sql_database_instance.{name}",
                f"Cloud SQL instance '{name}' has a public IP assigned (ipv4_enabled=true).",
                "Set ipv4_enabled = false and use Private IP with private_network.",
                {"instance": name, "ipv4_enabled": True, "open_network": False}
            ))
        else:
            findings.append(create_finding(
                "IAC-GCP-SQL-01", "Terraform GCP SQL Public IP", "Low",
                "PASS", f"google_sql_database_instance.{name}",
                f"Cloud SQL instance '{name}' does not have a public IP.",
                "No action required.",
                {"instance": name, "ipv4_enabled": False}
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
        "category": "IaC Database",
        "resource_type": "google_sql_database_instance",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
