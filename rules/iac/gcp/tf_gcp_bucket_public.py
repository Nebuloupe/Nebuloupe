import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect GCS buckets with public access via
    allUsers or allAuthenticatedUsers IAM bindings.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-GCP-GCS-01", "Terraform GCP Bucket Public Access", "Info",
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

    # Check google_storage_bucket_iam_member / binding for allUsers
    iam_member_pattern = re.compile(
        r'resource\s+"google_storage_bucket_iam_(?:member|binding)"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in iam_member_pattern.findall(all_content):
        member = re.search(r'member\s*=\s*"(allUsers|allAuthenticatedUsers)"', body, re.IGNORECASE)
        members = re.search(r'members\s*=\s*\[(.*?)\]', body, re.DOTALL)

        is_public = False
        if member:
            is_public = True
        if members and ("allUsers" in members.group(1) or "allAuthenticatedUsers" in members.group(1)):
            is_public = True

        if is_public:
            findings.append(create_finding(
                "IAC-GCP-GCS-01", "Terraform GCP Bucket Public IAM", "Critical",
                "FAIL", f"google_storage_bucket_iam.{name}",
                f"Storage bucket IAM '{name}' grants access to allUsers/allAuthenticatedUsers. "
                "All objects in the bucket are publicly accessible.",
                "Remove allUsers/allAuthenticatedUsers from IAM bindings. "
                "Use specific service accounts or user principals.",
                {"iam_resource": name, "public": True}
            ))

    # Check google_storage_bucket_access_control
    acl_pattern = re.compile(
        r'resource\s+"google_storage_bucket_access_control"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for name, body in acl_pattern.findall(all_content):
        entity = re.search(r'entity\s*=\s*"(allUsers|allAuthenticatedUsers)"', body, re.IGNORECASE)
        if entity:
            findings.append(create_finding(
                "IAC-GCP-GCS-01", "Terraform GCP Bucket Public ACL", "Critical",
                "FAIL", f"google_storage_bucket_access_control.{name}",
                f"Bucket ACL '{name}' grants access to {entity.group(1)}.",
                "Remove public entity from bucket ACL.",
                {"acl_resource": name, "entity": entity.group(1)}
            ))

    # Check uniform_bucket_level_access on buckets
    bucket_pattern = re.compile(
        r'resource\s+"google_storage_bucket"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for bucket_name, bucket_body in bucket_pattern.findall(all_content):
        uniform = re.search(r'uniform_bucket_level_access\s*=\s*(true|false)', bucket_body, re.IGNORECASE)
        if not uniform or uniform.group(1).lower() == "false":
            findings.append(create_finding(
                "IAC-GCP-GCS-01", "Terraform GCP Bucket Uniform Access", "Medium",
                "FAIL", f"google_storage_bucket.{bucket_name}",
                f"Bucket '{bucket_name}' does not have uniform_bucket_level_access enabled. "
                "Without this, legacy ACLs can grant unintended public access.",
                "Set uniform_bucket_level_access = true.",
                {"bucket": bucket_name, "uniform_access": False}
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
        "category": "IaC Storage",
        "resource_type": "google_storage_bucket",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
