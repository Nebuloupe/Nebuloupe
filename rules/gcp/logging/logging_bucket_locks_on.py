import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    logging_svc = discovery.build('logging', 'v2', cache_discovery=False)
    findings = []

    buckets_resp = logging_svc.projects().locations().buckets().list(
        parent=f"projects/{project_id}/locations/-"
    ).execute()

    buckets = buckets_resp.get('buckets', [])

    if not buckets:
        findings.append(create_finding(
            "GCP-LOG-04",
            "Log Bucket Retention Lock Enabled",
            "Medium",
            "FAIL",
            f"projects/{project_id}",
            "No log buckets found in this project.",
            "Create log buckets with retention locks to prevent log tampering.",
            {"bucket_count": 0}
        ))
        return findings

    for bucket in buckets:
        bucket_name = bucket['name'].split('/')[-1]
        retention_days = bucket.get('retentionDays', 0)
        locked = bucket.get('locked', False)

        # A locked bucket with sufficient retention is considered secure
        secure = locked and retention_days >= 365

        findings.append(create_finding(
            "GCP-LOG-04",
            "Log Bucket Retention Lock Enabled",
            "Medium" if not secure else "Low",
            "FAIL" if not secure else "PASS",
            project_id,
            bucket['name'],
            f"Log bucket '{bucket_name}' is {'not locked' if not locked else 'locked'} "
            f"with {retention_days} day(s) retention." if not secure
            else f"Log bucket '{bucket_name}' is locked with {retention_days}-day retention.",
            "Enable retention lock and set retention to at least 365 days to prevent log deletion or tampering." if not secure
            else "No action required.",
            {
                "bucket_name": bucket_name,
                "retention_days": retention_days,
                "locked": locked
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
        "project_id": project_id,
        "cloud_provider": "gcp",
        "category": "Logging",
        "resource_type": "gcp_logging_bucket",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/logging/docs/buckets"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
