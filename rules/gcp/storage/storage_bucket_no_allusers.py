import uuid
from google.cloud import storage


def run_check(project_id: str):
    findings = []
    client = storage.Client(project=project_id)

    try:
        buckets = list(client.list_buckets())
    except Exception as e:
        return [create_finding(
            "GCP-STG-01", "GCS Bucket No Public Access", "Critical", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing buckets: {e}",
            "Ensure storage.googleapis.com is enabled and caller has storage.buckets.list permission.",
            {"error": str(e)}
        )]

    for bucket in buckets:
        violations = []
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = binding.get("members", [])
                matched = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
                if matched:
                    violations.append({
                        "role": binding.get("role"),
                        "public_members": matched
                    })
        except Exception as e:
            findings.append(create_finding(
                "GCP-STG-01", "GCS Bucket No Public Access", "Critical", "ERROR",
                project_id, bucket.name,
                f"Error reading IAM policy for bucket '{bucket.name}': {e}",
                "Ensure caller has storage.buckets.getIamPolicy permission.",
                {"error": str(e)}
            ))
            continue

        status = "FAIL" if violations else "PASS"
        desc = (
            f"Bucket '{bucket.name}' grants access to {len(violations)} public member binding(s) "
            "(allUsers or allAuthenticatedUsers)."
            if violations
            else f"Bucket '{bucket.name}' has no public (allUsers/allAuthenticatedUsers) IAM bindings."
        )

        findings.append(create_finding(
            "GCP-STG-01", "GCS Bucket No Public Access",
            "Critical" if violations else "Low",
            status, project_id, bucket.name, desc,
            "Remove 'allUsers' and 'allAuthenticatedUsers' from all bucket IAM bindings. "
            "Use Uniform Bucket-Level Access and restrict to specific service accounts or groups.",
            {"public_bindings": violations, "bucket_location": bucket.location}
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
            "https://cloud.google.com/storage/docs/access-control/making-data-public",
            "https://cloud.google.com/storage/docs/public-access-prevention"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
