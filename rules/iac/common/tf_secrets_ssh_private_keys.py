import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect SSH private keys embedded directly
    in Terraform files (inline or file references to unprotected paths).
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-SEC-SSH-01", "Terraform SSH Private Key", "Info",
            "PASS", "N/A", "No Terraform files found.", "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    # Patterns for SSH private keys
    patterns = [
        (re.compile(r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----'), "Inline SSH Private Key"),
        (re.compile(r'private_key\s*=\s*"-----BEGIN'), "Private Key Assignment"),
        (re.compile(r'private_key_pem\s*=\s*"-----BEGIN'), "Private Key PEM Assignment"),
        (re.compile(r'ssh_private_key\s*=\s*"-----BEGIN'), "SSH Private Key Assignment"),
    ]

    # Also check for file() references to key files in unsafe locations
    file_key_pattern = re.compile(
        r'(?:private_key|ssh_key|key_data)\s*=\s*file\s*\(\s*"([^"]*(?:\.pem|\.key|id_rsa|id_ed25519)[^"]*)"\s*\)',
        re.IGNORECASE
    )

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            continue

        file_has_key = False

        for line_num, line in enumerate(lines, start=1):
            for pattern, label in patterns:
                if pattern.search(line):
                    file_has_key = True
                    findings.append(create_finding(
                        "IAC-SEC-SSH-01", f"Terraform {label}", "Critical",
                        "FAIL", tf_file,
                        f"{label} found at line {line_num} in {os.path.basename(tf_file)}. "
                        "Private keys in source code can be extracted by anyone with repo access.",
                        "Never embed private keys in Terraform files. Use Terraform's "
                        "tls_private_key resource for ephemeral keys, or reference keys "
                        "from a secrets manager.",
                        {"file": tf_file, "line": line_num, "pattern": label}
                    ))

            # Check file() references
            file_match = file_key_pattern.search(line)
            if file_match:
                key_path = file_match.group(1)
                file_has_key = True
                findings.append(create_finding(
                    "IAC-SEC-SSH-01", "Terraform SSH Key File Reference", "High",
                    "FAIL", tf_file,
                    f"SSH private key file reference '{key_path}' found at line {line_num} "
                    f"in {os.path.basename(tf_file)}. Ensure the key file is not committed "
                    "to version control.",
                    "Add key files to .gitignore. Consider using a secrets manager or "
                    "Terraform tls_private_key resource instead.",
                    {"file": tf_file, "line": line_num, "key_file": key_path}
                ))

        if not file_has_key:
            findings.append(create_finding(
                "IAC-SEC-SSH-01", "Terraform SSH Private Key", "Low",
                "PASS", tf_file,
                f"No embedded SSH private keys detected in {os.path.basename(tf_file)}.",
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
            "https://registry.terraform.io/providers/hashicorp/tls/latest/docs/resources/private_key"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
