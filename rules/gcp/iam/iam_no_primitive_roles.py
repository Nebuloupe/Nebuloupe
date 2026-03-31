import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2


def run_check(project_id: str):
    findings = []
    PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}

    try:
        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = client.get_iam_policy(request=request)

        violations = []
        for binding in policy.bindings:
            if binding.role in PRIMITIVE_ROLES:
                violations.append({
                    "role": binding.role,
                    "members": list(binding.members)
                })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"Found {len(violations)} primitive role binding(s) in project."
            if violations
            else "No primitive roles (Owner/Editor/Viewer) are assigned."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-01",
            check="No Primitive IAM Roles",
            severity="High",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Replace primitive roles with predefined or custom IAM roles "
                "that follow the principle of least privilege."
            ),
            evidence={"primitive_role_bindings": violations}
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-01",
            check="No Primitive IAM Roles",
            severity="High",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error retrieving IAM policy: {e}",
            rem="Ensure the caller has resourcemanager.projects.getIamPolicy permission.",
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
        "resource_type": "gcp_iam_policy",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/understanding-roles#primitive_roles",
            "https://cloud.google.com/iam/docs/using-iam-securely#least_privilege"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
