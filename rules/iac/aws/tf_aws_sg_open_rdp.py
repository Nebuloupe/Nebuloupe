import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect AWS Security Groups in Terraform that allow
    inbound RDP (port 3389) from 0.0.0.0/0 or ::/0 (unrestricted internet access).
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-SG-02", "Terraform SG Open RDP", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
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

    # Find all security group resources
    sg_pattern = re.compile(
        r'resource\s+"aws_security_group"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )
    sg_rule_pattern = re.compile(
        r'resource\s+"aws_security_group_rule"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # Check inline ingress blocks in security groups
    for sg_name, sg_body in sg_pattern.findall(all_content):
        ingress_blocks = re.findall(r'ingress\s*\{(.*?)\}', sg_body, re.DOTALL)
        open_rdp = False

        for ingress in ingress_blocks:
            from_port = re.search(r'from_port\s*=\s*(\d+)', ingress)
            to_port = re.search(r'to_port\s*=\s*(\d+)', ingress)

            if from_port and to_port:
                fp, tp = int(from_port.group(1)), int(to_port.group(1))
                if fp <= 3389 <= tp:
                    cidrs = re.findall(r'cidr_blocks\s*=\s*\[(.*?)\]', ingress, re.DOTALL)
                    ipv6_cidrs = re.findall(r'ipv6_cidr_blocks\s*=\s*\[(.*?)\]', ingress, re.DOTALL)
                    all_cidrs = " ".join(cidrs + ipv6_cidrs)
                    if '0.0.0.0/0' in all_cidrs or '::/0' in all_cidrs:
                        open_rdp = True

        if open_rdp:
            findings.append(create_finding(
                "IAC-AWS-SG-02", "Terraform SG Open RDP", "Critical",
                "FAIL", f"aws_security_group.{sg_name}",
                f"Security group '{sg_name}' allows inbound RDP (port 3389) from 0.0.0.0/0. "
                "Unrestricted RDP access exposes Windows instances to brute-force attacks "
                "and remote exploitation.",
                "Restrict RDP access to specific trusted CIDR ranges. Use a VPN or "
                "AWS Systems Manager Fleet Manager for remote desktop access instead.",
                {"security_group": sg_name, "port": 3389, "open_cidr": "0.0.0.0/0"}
            ))
        else:
            findings.append(create_finding(
                "IAC-AWS-SG-02", "Terraform SG Open RDP", "Low",
                "PASS", f"aws_security_group.{sg_name}",
                f"Security group '{sg_name}' does not allow unrestricted RDP access from the internet.",
                "No action required.",
                {"security_group": sg_name, "rdp_open": False}
            ))

    # Check standalone security group rules
    for rule_name, rule_body in sg_rule_pattern.findall(all_content):
        rule_type = re.search(r'type\s*=\s*"(ingress|egress)"', rule_body)
        if not rule_type or rule_type.group(1) != "ingress":
            continue

        from_port = re.search(r'from_port\s*=\s*(\d+)', rule_body)
        to_port = re.search(r'to_port\s*=\s*(\d+)', rule_body)

        if from_port and to_port:
            fp, tp = int(from_port.group(1)), int(to_port.group(1))
            if fp <= 3389 <= tp:
                cidrs = re.findall(r'cidr_blocks\s*=\s*\[(.*?)\]', rule_body, re.DOTALL)
                ipv6_cidrs = re.findall(r'ipv6_cidr_blocks\s*=\s*\[(.*?)\]', rule_body, re.DOTALL)
                all_cidrs = " ".join(cidrs + ipv6_cidrs)
                if '0.0.0.0/0' in all_cidrs or '::/0' in all_cidrs:
                    findings.append(create_finding(
                        "IAC-AWS-SG-02", "Terraform SG Rule Open RDP", "Critical",
                        "FAIL", f"aws_security_group_rule.{rule_name}",
                        f"Security group rule '{rule_name}' allows inbound RDP (port 3389) from 0.0.0.0/0.",
                        "Restrict the CIDR range to trusted IP ranges only.",
                        {"rule": rule_name, "port": 3389, "open_cidr": "0.0.0.0/0"}
                    ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    """Helper to maintain Nebuloupe finding schema"""
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "IaC Networking",
        "resource_type": "aws_security_group",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
