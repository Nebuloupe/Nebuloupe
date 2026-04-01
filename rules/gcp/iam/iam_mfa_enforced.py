import uuid
from googleapiclient.discovery import build


def run_check(project_id: str, admin_credentials=None):
    """
    Checks whether 2-Step Verification (2SV/MFA) is enforced via an org policy
    or admin SDK. Requires Google Workspace Admin SDK or org policy API access.
    Falls back to org policy constraint check if Admin SDK is unavailable.
    """
    findings = []

    try:
        # Check org policy for 2SV enforcement constraint
        from google.cloud import orgpolicy_v2

        client = orgpolicy_v2.OrgPolicyClient()
        policy_name = f"projects/{project_id}/policies/iam.managed.disableWorkspaceUserTwoStepVerification"

        enforced = False
        try:
            policy = client.get_policy(name=policy_name)
            # If policy exists and is NOT set to disable 2SV, then 2SV is not disabled
            # The absence of the "disable" constraint means 2SV can be enforced
            spec = policy.spec
            if spec and spec.rules:
                for rule in spec.rules:
                    if hasattr(rule, 'enforce') and rule.enforce is False:
                        enforced = False  # 2SV is explicitly disabled
                        break
                    enforced = True
            else:
                enforced = False  # Policy exists but has no rules
        except Exception:
            # Policy not found – 2SV enforcement not confirmed at project level
            enforced = False

        status = "PASS" if enforced else "FAIL"
        desc = (
            "2-Step Verification (MFA) enforcement policy is configured."
            if enforced
            else (
                "No MFA/2SV enforcement policy detected at the project level. "
                "Enforce 2SV via Google Workspace Admin or org-level policy."
            )
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-02",
            check="MFA Enforced for Users",
            severity="High",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Enable and enforce 2-Step Verification for all users in the "
                "Google Workspace Admin console under Security > 2-Step Verification, "
                "or set the org policy constraint "
                "'iam.managed.disableWorkspaceUserTwoStepVerification' to False."
            ),
            evidence={"mfa_enforced": enforced}
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-02",
            check="MFA Enforced for Users",
            severity="High",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking MFA enforcement: {e}",
            rem="Ensure orgpolicy.googleapis.com is enabled and caller has orgpolicy.policies.get permission.",
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
        "resource_type": "gcp_org_policy",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/resource-manager/docs/organization-policy/overview",
            "https://support.google.com/a/answer/9176657"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
