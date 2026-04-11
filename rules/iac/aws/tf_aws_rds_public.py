import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect RDS instances in Terraform that have
    publicly_accessible set to true, exposing databases to the internet.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-RDS-01", "Terraform RDS Public Access", "Info",
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

    # Match RDS instance resources
    rds_pattern = re.compile(
        r'resource\s+"aws_db_instance"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )
    # Also check RDS clusters
    rds_cluster_pattern = re.compile(
        r'resource\s+"aws_rds_cluster"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    # Check RDS instances
    for rds_name, rds_body in rds_pattern.findall(all_content):
        publicly_accessible = re.search(
            r'publicly_accessible\s*=\s*(true|false)', rds_body, re.IGNORECASE
        )

        if publicly_accessible and publicly_accessible.group(1).lower() == "true":
            findings.append(create_finding(
                "IAC-AWS-RDS-01", "Terraform RDS Public Access", "Critical",
                "FAIL", f"aws_db_instance.{rds_name}",
                f"RDS instance '{rds_name}' has publicly_accessible set to true. "
                "This exposes the database to the public internet, making it vulnerable "
                "to brute-force attacks and unauthorized access.",
                "Set publicly_accessible = false and access the database through a VPN, "
                "bastion host, or VPC peering connection.",
                {"rds_instance": rds_name, "publicly_accessible": True}
            ))
        elif publicly_accessible and publicly_accessible.group(1).lower() == "false":
            findings.append(create_finding(
                "IAC-AWS-RDS-01", "Terraform RDS Public Access", "Low",
                "PASS", f"aws_db_instance.{rds_name}",
                f"RDS instance '{rds_name}' has publicly_accessible set to false.",
                "No action required.",
                {"rds_instance": rds_name, "publicly_accessible": False}
            ))
        else:
            # publicly_accessible defaults to false in AWS provider, but flagging
            # as info since explicit is better than implicit
            findings.append(create_finding(
                "IAC-AWS-RDS-01", "Terraform RDS Public Access", "Low",
                "PASS", f"aws_db_instance.{rds_name}",
                f"RDS instance '{rds_name}' does not explicitly set publicly_accessible "
                "(defaults to false).",
                "Consider explicitly setting publicly_accessible = false for clarity.",
                {"rds_instance": rds_name, "publicly_accessible": "not_set (default: false)"}
            ))

    # Check RDS clusters
    for cluster_name, cluster_body in rds_cluster_pattern.findall(all_content):
        publicly_accessible = re.search(
            r'publicly_accessible\s*=\s*(true|false)', cluster_body, re.IGNORECASE
        )

        if publicly_accessible and publicly_accessible.group(1).lower() == "true":
            findings.append(create_finding(
                "IAC-AWS-RDS-01", "Terraform RDS Cluster Public Access", "Critical",
                "FAIL", f"aws_rds_cluster.{cluster_name}",
                f"RDS cluster '{cluster_name}' has publicly_accessible set to true. "
                "This exposes the entire database cluster to the public internet.",
                "Set publicly_accessible = false and use private networking for database access.",
                {"rds_cluster": cluster_name, "publicly_accessible": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AWS-RDS-01", "Terraform RDS Cluster Public Access", "Low",
                "PASS", f"aws_rds_cluster.{cluster_name}",
                f"RDS cluster '{cluster_name}' is not publicly accessible.",
                "No action required.",
                {"rds_cluster": cluster_name, "publicly_accessible": False}
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
        "category": "IaC Database",
        "resource_type": "aws_rds",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
