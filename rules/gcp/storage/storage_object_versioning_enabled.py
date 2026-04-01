import uuid
from google.cloud import storage


def run_check(project_id: str):
    findings = []
    client = storage.Client(project=project_id)

    try:
        buckets = list(client.list_buckets())
    except Exception as e:
        return [create_finding(
            "GCP-STG-03", "GCS Object Versioning Enabled", "Medium", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing buckets: {e}",
            "Ensure storage.googleapis.com is enabled and caller has storage.buckets.list permission.",
            {"error": str(e)}
        )]

    for bucket in buckets:
        try:
            bucket.reload()
            versioning_enabled = bucket.versioning_enabled
        except Exception as e:
            findings.append(create_finding(
                "GCP-STG-03", "GCS Object Versioning Enabled", "Medium", "ERROR",
                project_id, bucket.name,
                f"Error reading versioning config for bucket '{bucket.name}': {e}",
                "Ensure caller has storage.buckets.get permission.",
                {"error": str(e)}
            ))
            continue

        status = "PASS" if versioning_enabled else "FAIL"
        desc = (
            f"Bucket '{bucket.name}' has object versioning enabled."
            if versioning_enabled
            else f"Bucket '{bucket.name}' does not have object versioning enabled. "
                 "Accidental deletions or overwrites cannot be recovered."
        )

        findings.append(create_finding(
            "GCP-STG-03", "GCS Object Versioning Enabled",
            "Low" if versioning_enabled else "Medium",
            status, project_id, bucket.name, desc,
            "Enable object versioning on all GCS buckets storing important data to protect "
            "against accidental deletion and support data recovery.",
            {
                "versioning_enabled": versioning_enabled,
                "bucket_location": bucket.location,
                "storage_class": bucket.storage_class
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
            "https://cloud.google.com/storage/docs/object-versioning",
            "https://cloud.google.com/storage/docs/best-practices#data-protection"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
