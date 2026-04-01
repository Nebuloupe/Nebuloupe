import uuid
from datetime import datetime, timezone, timedelta
from google.cloud import iam_admin_v1


ROTATION_THRESHOLD_DAYS = 90


def run_check(project_id: str):
    findings = []
    violations = []
    all_keys = []

    try:
        client = iam_admin_v1.IAMClient()
        sa_request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        service_accounts = client.list_service_accounts(request=sa_request)

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=ROTATION_THRESHOLD_DAYS)

        for sa in service_accounts:
            key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                name=sa.name,
                key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
            )
            keys = client.list_service_account_keys(request=key_request)

            for key in keys.keys:
                valid_after = key.valid_after_time
                if valid_after and valid_after.ToDatetime(tzinfo=timezone.utc) < cutoff:
                    age_days = (now - valid_after.ToDatetime(tzinfo=timezone.utc)).days
                    violations.append({
                        "service_account": sa.email,
                        "key_name": key.name,
                        "created_at": valid_after.ToDatetime(tzinfo=timezone.utc).isoformat(),
                        "age_days": age_days
                    })
                all_keys.append({
                    "service_account": sa.email,
                    "key_name": key.name
                })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"{len(violations)} service account key(s) have not been rotated in over "
            f"{ROTATION_THRESHOLD_DAYS} days."
            if violations
            else f"All user-managed service account keys were rotated within {ROTATION_THRESHOLD_DAYS} days."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-03",
            check="Service Account Keys Rotated",
            severity="Medium",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                f"Rotate or delete service account keys older than {ROTATION_THRESHOLD_DAYS} days. "
                "Use Workload Identity Federation to eliminate long-lived keys where possible."
            ),
            evidence={
                "total_user_managed_keys": len(all_keys),
                "stale_keys": violations
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-03",
            check="Service Account Keys Rotated",
            severity="Medium",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking service account key rotation: {e}",
            rem="Ensure iam.googleapis.com is enabled and caller has iam.serviceAccountKeys.list permission.",
            evidence={"error": str(e)}
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
        "category": "IAM",
        "resource_type": "gcp_service_account_key",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/best-practices-service-accounts#rotate-keys",
            "https://cloud.google.com/iam/docs/workload-identity-federation"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
