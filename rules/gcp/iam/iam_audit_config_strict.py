import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2


# All three log types should be enabled for the "allServices" entry
REQUIRED_LOG_TYPES = {
    1,  # ADMIN_READ
    2,  # DATA_WRITE
    3,  # DATA_READ
}

LOG_TYPE_NAMES = {
    1: "ADMIN_READ",
    2: "DATA_WRITE",
    3: "DATA_READ"
}


def run_check(project_id: str):
    findings = []
    issues = []

    try:
        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = client.get_iam_policy(request=request)

        audit_configs = {ac.service: ac for ac in policy.audit_configs}

        # Check "allServices" entry
        all_services_config = audit_configs.get("allServices")
        if not all_services_config:
            issues.append({
                "issue": "Missing 'allServices' audit config — no default audit logging configured."
            })
        else:
            enabled_types = {alc.log_type for alc in all_services_config.audit_log_configs}
            missing_types = REQUIRED_LOG_TYPES - enabled_types
            if missing_types:
                issues.append({
                    "service": "allServices",
                    "missing_log_types": [LOG_TYPE_NAMES[t] for t in missing_types]
                })

            # Check for exempted principals in allServices (reduces audit coverage)
            for alc in all_services_config.audit_log_configs:
                if alc.exempted_members:
                    issues.append({
                        "service": "allServices",
                        "log_type": LOG_TYPE_NAMES.get(alc.log_type, alc.log_type),
                        "exempted_members": list(alc.exempted_members),
                        "issue": "Principals are exempted from audit logging."
                    })

        status = "FAIL" if issues else "PASS"
        desc = (
            f"Audit configuration has {len(issues)} issue(s): incomplete log types or exempted principals."
            if issues
            else "Audit logging is fully configured with DATA_READ, DATA_WRITE, and ADMIN_READ for allServices."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-09",
            check="Strict IAM Audit Config",
            severity="Medium",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Enable DATA_READ, DATA_WRITE, and ADMIN_READ audit log types for 'allServices' "
                "in the project IAM policy. Remove exemptions from audit log configs to ensure "
                "full audit coverage across all principals."
            ),
            evidence={
                "audit_config_issues": issues,
                "services_with_audit_config": list(audit_configs.keys())
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-09",
            check="Strict IAM Audit Config",
            severity="Medium",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking audit configuration: {e}",
            rem="Ensure resourcemanager.googleapis.com is enabled and caller has resourcemanager.projects.getIamPolicy.",
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
        "resource_type": "gcp_iam_audit_config",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/audit-logging",
            "https://cloud.google.com/logging/docs/audit/configure-data-access"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
