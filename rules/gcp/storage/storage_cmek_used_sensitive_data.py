import uuid
from google.cloud import storage


# Label key used to mark buckets containing sensitive data.
# Buckets tagged with this label are expected to use CMEK.
SENSITIVE_LABEL_KEY = "data-classification"
SENSITIVE_LABEL_VALUES = {"sensitive", "confidential", "pii", "restricted"}


def run_check(project_id: str):
    """
    Checks that GCS buckets labelled as sensitive use a Customer-Managed
    Encryption Key (CMEK) rather than Google-managed encryption.
    Buckets without the sensitive label are reported as informational PASS.
    """
    findings = []
    client = storage.Client(project=project_id)

    try:
        buckets = list(client.list_buckets())
    except Exception as e:
        return [create_finding(
            "GCP-STG-04", "GCS CMEK Used for Sensitive Buckets", "High", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing buckets: {e}",
            "Ensure storage.googleapis.com is enabled and caller has storage.buckets.list permission.",
            {"error": str(e)}
        )]

    for bucket in buckets:
        try:
            bucket.reload()
            labels = bucket.labels or {}
            classification = labels.get(SENSITIVE_LABEL_KEY, "").lower()
            is_sensitive = classification in SENSITIVE_LABEL_VALUES

            # default_kms_key_name is set only when CMEK is configured
            cmek_key = bucket.default_kms_key_name

            if is_sensitive:
                status = "PASS" if cmek_key else "FAIL"
                severity = "Low" if cmek_key else "High"
                desc = (
                    f"Sensitive bucket '{bucket.name}' (classification='{classification}') "
                    f"uses CMEK key: {cmek_key}."
                    if cmek_key
                    else f"Sensitive bucket '{bucket.name}' (classification='{classification}') "
                         "does not use a Customer-Managed Encryption Key (CMEK)."
                )
                rem = (
                    "No action required — CMEK is configured."
                    if cmek_key
                    else "Configure a Cloud KMS CMEK key as the default encryption key for this bucket. "
                         "Rotate existing objects using a rewrite operation to apply CMEK retroactively."
                )
            else:
                # Non-sensitive bucket — informational PASS
                status = "PASS"
                severity = "Low"
                desc = (
                    f"Bucket '{bucket.name}' is not labelled as sensitive "
                    f"('{SENSITIVE_LABEL_KEY}' label absent or value='{classification}'). "
                    + (f"CMEK key is configured: {cmek_key}." if cmek_key else "Uses Google-managed encryption.")
                )
                rem = (
                    f"If this bucket stores sensitive data, add the label "
                    f"'{SENSITIVE_LABEL_KEY}=sensitive' and configure a CMEK key."
                )

        except Exception as e:
            findings.append(create_finding(
                "GCP-STG-04", "GCS CMEK Used for Sensitive Buckets", "High", "ERROR",
                project_id, bucket.name,
                f"Error reading encryption config for bucket '{bucket.name}': {e}",
                "Ensure caller has storage.buckets.get permission.",
                {"error": str(e)}
            ))
            continue

        findings.append(create_finding(
            "GCP-STG-04", "GCS CMEK Used for Sensitive Buckets",
            severity, status, project_id, bucket.name, desc, rem,
            {
                "is_sensitive": is_sensitive,
                "data_classification": classification or None,
                "cmek_key": cmek_key,
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
            "https://cloud.google.com/storage/docs/encryption/customer-managed-keys",
            "https://cloud.google.com/kms/docs/creating-keys"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
