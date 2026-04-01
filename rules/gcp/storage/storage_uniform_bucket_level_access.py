import uuid
from google.cloud import storage


def run_check(project_id: str):
    findings = []
    client = storage.Client(project=project_id)

    try:
        buckets = list(client.list_buckets())
    except Exception as e:
        return [create_finding(
            "GCP-STG-02", "GCS Uniform Bucket-Level Access", "High", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing buckets: {e}",
            "Ensure storage.googleapis.com is enabled and caller has storage.buckets.list permission.",
            {"error": str(e)}
        )]

    for bucket in buckets:
        try:
            # Reload to get full metadata including iamConfiguration
            bucket.reload()
            iam_config = bucket.iam_configuration
            ubla_enabled = iam_config.uniform_bucket_level_access_enabled
        except Exception as e:
            findings.append(create_finding(
                "GCP-STG-02", "GCS Uniform Bucket-Level Access", "High", "ERROR",
                project_id, bucket.name,
                f"Error reading bucket metadata for '{bucket.name}': {e}",
                "Ensure caller has storage.buckets.get permission.",
                {"error": str(e)}
            ))
            continue

        status = "PASS" if ubla_enabled else "FAIL"
        desc = (
            f"Bucket '{bucket.name}' has Uniform Bucket-Level Access enabled."
            if ubla_enabled
            else f"Bucket '{bucket.name}' does not have Uniform Bucket-Level Access enabled. "
                 "Object-level ACLs may allow unintended access."
        )

        findings.append(create_finding(
            "GCP-STG-02", "GCS Uniform Bucket-Level Access",
            "Low" if ubla_enabled else "High",
            status, project_id, bucket.name, desc,
            "Enable Uniform Bucket-Level Access on all buckets to disable legacy ACLs "
            "and enforce IAM-only access control.",
            {
                "uniform_bucket_level_access_enabled": ubla_enabled,
                "bucket_location": bucket.location
            }
        ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Storage",
        "resource_type": "gcp_storage_bucket",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/storage/docs/uniform-bucket-level-access",
            "https://cloud.google.com/storage/docs/best-practices#access-control"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
