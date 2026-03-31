import uuid
from google.cloud import iam_admin_v1


# Acceptable maximum number of user-managed keys per service account
MAX_KEYS_PER_SA = 1


def run_check(project_id: str):
    findings = []
    violations = []
    total_keys = 0

    try:
        client = iam_admin_v1.IAMClient()
        sa_request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        service_accounts = client.list_service_accounts(request=sa_request)

        for sa in service_accounts:
            key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                name=sa.name,
                key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
            )
            keys_response = client.list_service_account_keys(request=key_request)
            keys = list(keys_response.keys)
            total_keys += len(keys)

            if len(keys) > MAX_KEYS_PER_SA:
                violations.append({
                    "service_account": sa.email,
                    "key_count": len(keys),
                    "keys": [k.name for k in keys]
                })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"{len(violations)} service account(s) have more than {MAX_KEYS_PER_SA} "
            f"user-managed key(s), increasing credential exposure risk."
            if violations
            else "All service accounts have a minimal number of user-managed keys."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-04",
            check="User-Managed Service Account Keys Minimized",
            severity="Medium",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                f"Limit user-managed keys to {MAX_KEYS_PER_SA} per service account. "
                "Prefer Workload Identity Federation or short-lived credentials over "
                "persistent user-managed keys."
            ),
            evidence={
                "total_user_managed_keys": total_keys,
                "service_accounts_exceeding_limit": violations
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-04",
            check="User-Managed Service Account Keys Minimized",
            severity="Medium",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking service account keys: {e}",
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
            "https://cloud.google.com/iam/docs/best-practices-service-accounts#minimize-keys",
            "https://cloud.google.com/iam/docs/workload-identity-federation"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
