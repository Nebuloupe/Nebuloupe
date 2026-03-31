import uuid
from googleapiclient.discovery import build


# Label key used to identify disks/instances that require CSEK.
# Disks tagged with this label are expected to use CSEK or CMEK.
SENSITIVE_LABEL_KEY = "data-classification"
SENSITIVE_LABEL_VALUES = {"sensitive", "confidential", "pii", "restricted"}


def run_check(project_id: str):
    """
    Checks that persistent disks attached to sensitive instances use
    Customer-Supplied Encryption Keys (CSEK) or Customer-Managed Encryption
    Keys (CMEK). Disks using only Google-managed encryption on sensitive
    workloads are flagged.

    Note: CSEK key material is never stored by GCP; only a SHA-256 hash is
    visible in the API. The presence of diskEncryptionKey.sha256 confirms CSEK.
    CMEK is confirmed by the presence of diskEncryptionKey.kmsKeyName.
    """
    findings = []

    try:
        service = build("compute", "v1")
        agg_disks = service.disks().aggregatedList(project=project_id).execute()
    except Exception as e:
        return [create_finding(
            "GCP-CMP-08", "CSEK Disk Encryption", "High", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error listing Compute disks: {e}",
            "Ensure compute.googleapis.com is enabled and caller has compute.disks.list permission.",
            {"error": str(e)}
        )]

    disk_count = 0
    for zone_data in agg_disks.get("items", {}).values():
        for disk in zone_data.get("disks", []):
            disk_count += 1
            disk_name = disk.get("name")
            zone = disk.get("zone", "").split("/")[-1]
            labels = disk.get("labels", {})
            classification = labels.get(SENSITIVE_LABEL_KEY, "").lower()
            is_sensitive = classification in SENSITIVE_LABEL_VALUES

            enc_key = disk.get("diskEncryptionKey", {})
            csek_sha256 = enc_key.get("sha256")       # CSEK confirmed
            cmek_key = enc_key.get("kmsKeyName")       # CMEK confirmed

            has_csek = bool(csek_sha256)
            has_cmek = bool(cmek_key)
            has_customer_key = has_csek or has_cmek
            encryption_type = (
                "CSEK" if has_csek else
                "CMEK" if has_cmek else
                "Google-managed"
            )

            if is_sensitive:
                status = "PASS" if has_customer_key else "FAIL"
                severity = "Low" if has_customer_key else "High"
                desc = (
                    f"Sensitive disk '{disk_name}' (classification='{classification}') "
                    f"uses {encryption_type} encryption."
                    if has_customer_key
                    else f"Sensitive disk '{disk_name}' (classification='{classification}') "
                         "uses only Google-managed encryption — CSEK or CMEK is required."
                )
                rem = (
                    "No action required — customer-managed encryption is in place."
                    if has_customer_key
                    else "Re-create the disk with a CSEK key or configure CMEK via Cloud KMS. "
                         "CSEK keys must be supplied at every disk attach/detach operation."
                )
            else:
                status = "PASS"
                severity = "Low"
                desc = (
                    f"Disk '{disk_name}' is not labelled as sensitive "
                    f"('{SENSITIVE_LABEL_KEY}' absent or value='{classification}'). "
                    f"Using {encryption_type} encryption."
                )
                rem = (
                    f"If this disk stores sensitive data, add label "
                    f"'{SENSITIVE_LABEL_KEY}=sensitive' and configure CSEK or CMEK."
                )

            findings.append(create_finding(
                "GCP-CMP-08", "CSEK Disk Encryption",
                severity, status, project_id, disk_name, zone, desc, rem,
                {
                    "is_sensitive": is_sensitive,
                    "data_classification": classification or None,
                    "encryption_type": encryption_type,
                    "csek_sha256_present": has_csek,
                    "cmek_key": cmek_key,
                    "zone": zone,
                    "disk_size_gb": disk.get("sizeGb"),
                    "disk_type": disk.get("type", "").split("/")[-1]
                }
            ))

    if disk_count == 0:
        findings.append(create_finding(
            "GCP-CMP-08", "CSEK Disk Encryption", "Low", "PASS",
            project_id, f"projects/{project_id}", "global",
            "No persistent disks found in this project.",
            "No action required.", {"disk_count": 0}
        ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, region, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Compute",
        "resource_type": "gcp_compute_disk",
        "resource_id": res_id,
        "project_id": project_id,
        "region": region,
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/compute/docs/disks/customer-supplied-encryption",
            "https://cloud.google.com/compute/docs/disks/customer-managed-encryption"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
