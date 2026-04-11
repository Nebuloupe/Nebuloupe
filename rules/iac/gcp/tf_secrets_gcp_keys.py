import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect hardcoded GCP service account keys or
    credentials in Terraform files.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-SEC-01", "Terraform GCP Hardcoded Keys", "Info",
            "PASS", "N/A", "No Terraform files found.", "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    patterns = [
        (re.compile(r'credentials\s*=\s*file\s*\(\s*"([^"]*\.json)"', re.IGNORECASE), "GCP JSON Key File Path"),
        (re.compile(r'"private_key":\s*"-----BEGIN', re.IGNORECASE), "GCP Private Key Inline"),
        (re.compile(r'"private_key_id":\s*"[a-f0-9]{40}"', re.IGNORECASE), "GCP Private Key ID"),
        (re.compile(r'credentials\s*=\s*"(\{.*?private_key.*?\})"', re.DOTALL | re.IGNORECASE), "GCP Inline Credential JSON"),
    ]

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception:
            continue

        file_has_secret = False
        for line_num, line in enumerate(lines, start=1):
            for pattern, label in patterns:
                if pattern.search(line):
                    file_has_secret = True
                    findings.append(create_finding(
                        "IAC-GCP-SEC-01", f"Terraform {label}", "Critical",
                        "FAIL", tf_file,
                        f"Hardcoded {label} found at line {line_num} in {os.path.basename(tf_file)}. "
                        "GCP service account credentials in source code risk full project compromise.",
                        "Use Workload Identity Federation, application default credentials, "
                        "or a secrets manager instead of hardcoded key files.",
                        {"file": tf_file, "line": line_num, "pattern": label}
                    ))

        if not file_has_secret:
            findings.append(create_finding(
                "IAC-GCP-SEC-01", "Terraform GCP Hardcoded Keys", "Low",
                "PASS", tf_file,
                f"No hardcoded GCP credentials detected in {os.path.basename(tf_file)}.",
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
        "cloud_provider": "gcp",
        "category": "IaC Secrets",
        "resource_type": "terraform_file",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/guides/provider_reference#authentication"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
