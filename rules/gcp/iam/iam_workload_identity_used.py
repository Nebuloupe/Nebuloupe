import uuid
from google.cloud import iam_admin_v1


def run_check(project_id: str):
    """
    Checks whether Workload Identity Federation pools exist for the project,
    indicating that external workloads use short-lived tokens rather than
    long-lived service account keys.
    """
    findings = []

    try:
        # Check for Workload Identity Pools at project level
        wif_client = iam_admin_v1.WorkloadIdentityPoolsClient()
        parent = f"projects/{project_id}/locations/global"

        pools = list(wif_client.list_workload_identity_pools(parent=parent))
        active_pools = [p for p in pools if not p.disabled]

        # Also check total user-managed SA keys as a complementary signal
        sa_client = iam_admin_v1.IAMClient()
        sa_request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        service_accounts = list(sa_client.list_service_accounts(request=sa_request))

        total_user_keys = 0
        sa_key_details = []
        for sa in service_accounts:
            key_request = iam_admin_v1.ListServiceAccountKeysRequest(
                name=sa.name,
                key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
            )
            keys = list(sa_client.list_service_account_keys(request=key_request).keys)
            if keys:
                total_user_keys += len(keys)
                sa_key_details.append({
                    "service_account": sa.email,
                    "user_managed_key_count": len(keys)
                })

        # PASS if WIF pools exist; FAIL if none exist (especially if user-managed keys are in use)
        has_wif = len(active_pools) > 0
        status = "PASS" if has_wif else "FAIL"

        desc = (
            f"Workload Identity Federation is configured with {len(active_pools)} active pool(s). "
            f"The project also has {total_user_keys} user-managed service account key(s) — "
            "consider eliminating them in favour of WIF."
            if has_wif and total_user_keys > 0
            else (
                f"Workload Identity Federation is configured with {len(active_pools)} active pool(s)."
                if has_wif
                else (
                    f"No Workload Identity Federation pools found. The project uses "
                    f"{total_user_keys} user-managed service account key(s) for external authentication."
                )
            )
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-10",
            check="Workload Identity Federation Used",
            severity="Medium",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Configure Workload Identity Federation to allow external workloads "
                "(CI/CD pipelines, on-prem services, other clouds) to impersonate "
                "service accounts using short-lived tokens. This eliminates the need "
                "for long-lived user-managed service account keys."
            ),
            evidence={
                "workload_identity_pools": [
                    {"name": p.name, "display_name": p.display_name, "disabled": p.disabled}
                    for p in pools
                ],
                "active_pool_count": len(active_pools),
                "total_user_managed_keys": total_user_keys,
                "service_accounts_with_keys": sa_key_details
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-10",
            check="Workload Identity Federation Used",
            severity="Medium",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking Workload Identity Federation configuration: {e}",
            rem="Ensure iam.googleapis.com is enabled and caller has iam.workloadIdentityPools.list permission.",
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
        "resource_type": "gcp_workload_identity_pool",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/workload-identity-federation",
            "https://cloud.google.com/iam/docs/best-practices-service-accounts#use-wif"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
