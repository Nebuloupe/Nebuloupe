import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect S3 buckets in Terraform that lack a
    public access block or have any of the four block settings set to false.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-S3-01", "Terraform S3 Public Access Block", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    # Patterns to detect S3 buckets and public access block configuration
    bucket_pattern = re.compile(
        r'resource\s+"aws_s3_bucket"\s+"(\w+)"\s*\{',
        re.MULTILINE
    )
    public_access_block_pattern = re.compile(
        r'resource\s+"aws_s3_bucket_public_access_block"\s+"(\w+)"\s*\{(.*?)\}',
        re.DOTALL
    )
    block_settings = [
        "block_public_acls",
        "block_public_policy",
        "ignore_public_acls",
        "restrict_public_buckets"
    ]

    all_content = ""
    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                all_content += f"\n# FILE: {tf_file}\n" + f.read()
        except Exception:
            continue

    # Find all S3 buckets declared
    s3_buckets = bucket_pattern.findall(all_content)
    public_access_blocks = public_access_block_pattern.findall(all_content)

    # Map access blocks by checking if they reference a known bucket
    protected_buckets = set()
    for block_name, block_body in public_access_blocks:
        # Check if all four settings are set to true
        all_enabled = True
        for setting in block_settings:
            setting_match = re.search(rf'{setting}\s*=\s*(true|false)', block_body, re.IGNORECASE)
            if not setting_match or setting_match.group(1).lower() != "true":
                all_enabled = False
                break

        # Try to extract which bucket this block references
        bucket_ref = re.search(r'bucket\s*=\s*aws_s3_bucket\.(\w+)', block_body)
        bucket_id = bucket_ref.group(1) if bucket_ref else block_name

        if all_enabled:
            protected_buckets.add(bucket_id)
        else:
            findings.append(create_finding(
                "IAC-AWS-S3-01", "Terraform S3 Public Access Block", "High",
                "FAIL", f"aws_s3_bucket.{bucket_id}",
                f"S3 bucket '{bucket_id}' has an incomplete public access block. "
                "One or more of the four block settings is set to false or missing.",
                "Ensure all four settings (block_public_acls, block_public_policy, "
                "ignore_public_acls, restrict_public_buckets) are set to true.",
                {"bucket": bucket_id, "block_name": block_name, "missing_or_false": True}
            ))

    # Check for buckets without any public access block
    for bucket in s3_buckets:
        if bucket not in protected_buckets:
            # Check if it already got a FAIL finding above
            already_reported = any(
                f["resource_id"] == f"aws_s3_bucket.{bucket}" for f in findings
            )
            if not already_reported:
                findings.append(create_finding(
                    "IAC-AWS-S3-01", "Terraform S3 Public Access Block", "High",
                    "FAIL", f"aws_s3_bucket.{bucket}",
                    f"S3 bucket '{bucket}' does not have an aws_s3_bucket_public_access_block resource defined. "
                    "Without a public access block, the bucket may be exposed to the internet.",
                    "Add an aws_s3_bucket_public_access_block resource with all four settings set to true.",
                    {"bucket": bucket, "public_access_block": "missing"}
                ))
            continue

        findings.append(create_finding(
            "IAC-AWS-S3-01", "Terraform S3 Public Access Block", "Low",
            "PASS", f"aws_s3_bucket.{bucket}",
            f"S3 bucket '{bucket}' has a fully configured public access block.",
            "No action required.",
            {"bucket": bucket, "public_access_block": "fully_enabled"}
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
        "category": "IaC Storage",
        "resource_type": "aws_s3_bucket",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
