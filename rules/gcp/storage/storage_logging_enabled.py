import uuid
from google.cloud import storage


def run_check(project_id: str):
    findings = []
    client = storage.Client(project=project_id)

    try:
        buckets = list(client.list_buckets())
    except Exception as e:
        return [create_finding(
            "GCP-STG-05", "GCS Bucket Logging Enabled", "Medium", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing buckets: {e}",
            "Ensure storage.googleapis.com is enabled and caller has storage.buckets.list permission.",
            {"error": str(e)}
        )]

    for bucket in buckets:
        try:
            bucket.reload()
            log_bucket = bucket.logging.get("logBucket") if bucket.logging else None
            log_prefix = bucket.logging.get("logObjectPrefix") if bucket.logging else None
            logging_enabled = bool(log_bucket)
        except Exception as e:
            findings.append(create_finding(
                "GCP-STG-05", "GCS Bucket Logging Enabled", "Medium", "ERROR",
                project_id, bucket.name,
                f"Error reading logging config for bucket '{bucket.name}': {e}",
                "Ensure caller has storage.buckets.get permission.",
                {"error": str(e)}
            ))
            continue

        status = "PASS" if logging_enabled else "FAIL"
        desc = (
            f"Bucket '{bucket.name}' has access logging enabled. "
            f"Logs are delivered to bucket '{log_bucket}' with prefix '{log_prefix}'."
            if logging_enabled
            else f"Bucket '{bucket.name}' does not have access logging enabled. "
                 "Storage access activity cannot be audited."
        )

        findings.append(create_finding(
            "GCP-STG-05", "GCS Bucket Logging Enabled",
            "Low" if logging_enabled else "Medium",
            status, project_id, bucket.name, desc,
            "Enable GCS access logging for each bucket by specifying a log bucket destination. "
            "Use a dedicated logging bucket and configure lifecycle rules to manage log retention.",
            {
                "logging_enabled": logging_enabled,
                "log_bucket": log_bucket,
                "log_prefix": log_prefix,
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
            "https://cloud.google.com/storage/docs/access-logs",
            "https://cloud.google.com/storage/docs/best-practices#logging"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
