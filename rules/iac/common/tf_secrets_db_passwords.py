import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect hardcoded database passwords in Terraform files.
    Catches common patterns for RDS, Cloud SQL, Azure SQL, and generic DB resources.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-SEC-DB-01", "Terraform Hardcoded DB Password", "Info",
            "PASS", "N/A", "No Terraform files found.", "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    # Patterns for database passwords (matches password = "..." but not password = var.xxx)
    patterns = [
        re.compile(r'(?:admin_password|password|master_password|db_password)\s*=\s*"([^"$]{4,})"', re.IGNORECASE),
        re.compile(r'(?:administrator_login_password)\s*=\s*"([^"$]{4,})"', re.IGNORECASE),
        re.compile(r'(?:root_password)\s*=\s*"([^"$]{4,})"', re.IGNORECASE),
    ]

    # Exclusion patterns (variable references, functions, etc.)
    exclusions = re.compile(r'^\$\{|^var\.|^local\.|^data\.|^module\.')

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception:
            continue

        file_has_password = False
        for line_num, line in enumerate(lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('#') or stripped.startswith('//'):
                continue

            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    value = match.group(1)
                    # Skip variable references
                    if exclusions.match(value):
                        continue
                    file_has_password = True
                    findings.append(create_finding(
                        "IAC-SEC-DB-01", "Terraform Hardcoded DB Password", "Critical",
                        "FAIL", tf_file,
                        f"Hardcoded database password found at line {line_num} in "
                        f"{os.path.basename(tf_file)}. Plaintext passwords in source code "
                        "are a critical security risk.",
                        "Use Terraform variables with sensitive = true, or reference secrets "
                        "from a vault (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager).",
                        {"file": tf_file, "line": line_num, "field": "database password"}
                    ))

        if not file_has_password:
            findings.append(create_finding(
                "IAC-SEC-DB-01", "Terraform Hardcoded DB Password", "Low",
                "PASS", tf_file,
                f"No hardcoded database passwords detected in {os.path.basename(tf_file)}.",
                "No action required.",
                {"file": tf_file, "status": "clean"}
            ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "multi-cloud",
        "category": "IaC Secrets",
        "resource_type": "terraform_file",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
