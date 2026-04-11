import uuid
import os
import re
import glob


# Patterns that match hardcoded AWS access keys and secret keys in Terraform files
AWS_ACCESS_KEY_PATTERN = re.compile(
    r'(?:access_key|aws_access_key_id)\s*=\s*"((?:AKIA|ASIA)[A-Z0-9]{16})"',
    re.IGNORECASE
)
AWS_SECRET_KEY_PATTERN = re.compile(
    r'(?:secret_key|aws_secret_access_key)\s*=\s*"([A-Za-z0-9/+=]{40})"',
    re.IGNORECASE
)


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect hardcoded AWS access keys and secret keys
    embedded directly in Terraform configuration files.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-SEC-01", "Terraform AWS Hardcoded Keys", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan for hardcoded AWS keys.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            continue

        file_has_secret = False

        for line_num, line in enumerate(lines, start=1):
            # Check for hardcoded access key IDs
            if AWS_ACCESS_KEY_PATTERN.search(line):
                file_has_secret = True
                findings.append(create_finding(
                    "IAC-AWS-SEC-01", "Terraform AWS Hardcoded Access Key", "Critical",
                    "FAIL", tf_file,
                    f"Hardcoded AWS Access Key ID found at line {line_num} in {os.path.basename(tf_file)}. "
                    "Hardcoded credentials can be leaked via version control and pose a severe compromise risk.",
                    "Remove hardcoded credentials. Use environment variables, AWS IAM roles, "
                    "or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) instead.",
                    {"file": tf_file, "line": line_num, "pattern": "AWS Access Key ID (AKIA/ASIA...)"}
                ))

            # Check for hardcoded secret access keys
            if AWS_SECRET_KEY_PATTERN.search(line):
                file_has_secret = True
                findings.append(create_finding(
                    "IAC-AWS-SEC-01", "Terraform AWS Hardcoded Secret Key", "Critical",
                    "FAIL", tf_file,
                    f"Hardcoded AWS Secret Access Key found at line {line_num} in {os.path.basename(tf_file)}. "
                    "Secret keys in source code are a critical exposure risk.",
                    "Remove hardcoded credentials immediately. Rotate the compromised key pair and "
                    "use IAM roles or a secrets manager for credential injection.",
                    {"file": tf_file, "line": line_num, "pattern": "AWS Secret Access Key (40-char)"}
                ))

        if not file_has_secret:
            findings.append(create_finding(
                "IAC-AWS-SEC-01", "Terraform AWS Hardcoded Keys", "Low",
                "PASS", tf_file,
                f"No hardcoded AWS keys detected in {os.path.basename(tf_file)}.",
                "No action required.",
                {"file": tf_file, "status": "clean"}
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
        "category": "IaC Secrets",
        "resource_type": "terraform_file",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration",
            "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
