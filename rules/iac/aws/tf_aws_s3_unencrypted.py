import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect S3 buckets in Terraform that do not have
    server-side encryption configured via aws_s3_bucket_server_side_encryption_configuration.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-S3-02", "Terraform S3 Encryption", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    # Patterns
    bucket_pattern = re.compile(
        r'resource\s+"aws_s3_bucket"\s+"(\w+)"\s*\{',
        re.MULTILINE
    )
    # Modern approach: separate encryption resource (AWS provider >= 4.x)
    encryption_resource_pattern = re.compile(
        r'resource\s+"aws_s3_bucket_server_side_encryption_configuration"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )
    # Legacy approach: server_side_encryption_configuration block inline
    legacy_encryption_pattern = re.compile(
        r'server_side_encryption_configuration\s*\{',
        re.MULTILINE
    )

    all_content = ""
    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                all_content += f"\n# FILE: {tf_file}\n" + f.read()
        except Exception:
            continue

    s3_buckets = bucket_pattern.findall(all_content)

    # Find encryption resources and map them to buckets
    encrypted_buckets = set()

    # Check modern separate encryption resources
    for enc_name, enc_body in encryption_resource_pattern.findall(all_content):
        bucket_ref = re.search(r'bucket\s*=\s*aws_s3_bucket\.(\w+)', enc_body)
        if bucket_ref:
            encrypted_buckets.add(bucket_ref.group(1))
        else:
            encrypted_buckets.add(enc_name)

    # Check for inline legacy encryption in each bucket block
    bucket_blocks = re.findall(
        r'resource\s+"aws_s3_bucket"\s+"(\w+)"\s*\{(.*?)\n\}',
        all_content, re.DOTALL
    )
    for bucket_name, bucket_body in bucket_blocks:
        if legacy_encryption_pattern.search(bucket_body):
            encrypted_buckets.add(bucket_name)

    for bucket in s3_buckets:
        if bucket in encrypted_buckets:
            findings.append(create_finding(
                "IAC-AWS-S3-02", "Terraform S3 Encryption", "Low",
                "PASS", f"aws_s3_bucket.{bucket}",
                f"S3 bucket '{bucket}' has server-side encryption configured.",
                "No action required.",
                {"bucket": bucket, "encryption": "configured"}
            ))
        else:
            findings.append(create_finding(
                "IAC-AWS-S3-02", "Terraform S3 Encryption", "Medium",
                "FAIL", f"aws_s3_bucket.{bucket}",
                f"S3 bucket '{bucket}' does not have server-side encryption configured. "
                "Data at rest in this bucket will not be encrypted, risking data exposure "
                "if the bucket is compromised.",
                "Add an aws_s3_bucket_server_side_encryption_configuration resource with "
                "AES256 or aws:kms as the SSE algorithm.",
                {"bucket": bucket, "encryption": "missing"}
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
        "category": "IaC Encryption",
        "resource_type": "aws_s3_bucket",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
