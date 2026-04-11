import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect GCP Compute instances with public IP
    addresses assigned via access_config block.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-VM-01", "Terraform GCP Compute Public IP", "Info",
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

    instance_pattern = re.compile(
        r'resource\s+"google_compute_instance"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in instance_pattern.findall(all_content):
        # access_config block inside network_interface gives the instance a public IP
        network_interfaces = re.findall(r'network_interface\s*\{(.*?)\}', body, re.DOTALL)
        has_public_ip = False

        for ni in network_interfaces:
            if re.search(r'access_config\s*\{', ni):
                has_public_ip = True

        if has_public_ip:
            findings.append(create_finding(
                "IAC-GCP-VM-01", "Terraform GCP Compute Public IP", "High",
                "FAIL", f"google_compute_instance.{name}",
                f"Compute instance '{name}' has an access_config block, assigning it a "
                "public IP address. This directly exposes the VM to the internet.",
                "Remove the access_config block from network_interface. "
                "Use Cloud NAT for outbound internet access and IAP for SSH/RDP.",
                {"instance": name, "public_ip": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-GCP-VM-01", "Terraform GCP Compute Public IP", "Low",
                "PASS", f"google_compute_instance.{name}",
                f"Compute instance '{name}' does not have a public IP assigned.",
                "No action required.",
                {"instance": name, "public_ip": False}
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
        "category": "IaC Compute",
        "resource_type": "google_compute_instance",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
