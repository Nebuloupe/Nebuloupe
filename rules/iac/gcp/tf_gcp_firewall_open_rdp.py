import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect GCP firewall rules allowing inbound RDP (port 3389)
    from 0.0.0.0/0.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-FW-02", "Terraform GCP Firewall Open RDP", "Info",
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

    fw_pattern = re.compile(
        r'resource\s+"google_compute_firewall"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for fw_name, fw_body in fw_pattern.findall(all_content):
        direction = re.search(r'direction\s*=\s*"(\w+)"', fw_body, re.IGNORECASE)
        if direction and direction.group(1).upper() == "EGRESS":
            continue

        source_ranges = re.search(r'source_ranges\s*=\s*\[(.*?)\]', fw_body, re.DOTALL)
        is_open = False
        if source_ranges and '0.0.0.0/0' in source_ranges.group(1):
            is_open = True

        allow_blocks = re.findall(r'allow\s*\{(.*?)\}', fw_body, re.DOTALL)
        allows_rdp = False
        for allow in allow_blocks:
            ports = re.search(r'ports\s*=\s*\[(.*?)\]', allow, re.DOTALL)
            protocol = re.search(r'protocol\s*=\s*"(\w+)"', allow)
            
            if protocol and protocol.group(1).lower() == "all":
                allows_rdp = True
            elif ports:
                port_list = ports.group(1)
                if '"3389"' in port_list or "'3389'" in port_list:
                    allows_rdp = True

        if is_open and allows_rdp:
            findings.append(create_finding(
                "IAC-GCP-FW-02", "Terraform GCP Firewall Open RDP", "Critical",
                "FAIL", f"google_compute_firewall.{fw_name}",
                f"Firewall rule '{fw_name}' allows inbound RDP (port 3389) from 0.0.0.0/0. "
                "Windows instances are exposed to brute-force and remote exploitation.",
                "Restrict source_ranges to specific trusted CIDR ranges. "
                "Use IAP for secure remote desktop access.",
                {"firewall": fw_name, "port": 3389, "source": "0.0.0.0/0"}
            ))
        elif allows_rdp and not is_open:
            findings.append(create_finding(
                "IAC-GCP-FW-02", "Terraform GCP Firewall Open RDP", "Low",
                "PASS", f"google_compute_firewall.{fw_name}",
                f"Firewall rule '{fw_name}' allows RDP but from restricted sources.",
                "No action required.",
                {"firewall": fw_name, "rdp_restricted": True}
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
        "category": "IaC Networking",
        "resource_type": "google_compute_firewall",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_firewall"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
