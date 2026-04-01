import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2


ANONYMOUS_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


def run_check(project_id: str):
    findings = []
    violations = []

    try:
        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = client.get_iam_policy(request=request)

        for binding in policy.bindings:
            matched = ANONYMOUS_MEMBERS.intersection(set(binding.members))
            if matched:
                violations.append({
                    "role": binding.role,
                    "anonymous_members": list(matched)
                })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"Project IAM policy grants {len(violations)} role(s) to 'allUsers' or "
            "'allAuthenticatedUsers', allowing anonymous or unauthenticated access."
            if violations
            else "No anonymous (allUsers/allAuthenticatedUsers) IAM bindings found at the project level."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-07",
            check="No Anonymous or Public IAM Access",
            severity="Critical",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Remove 'allUsers' and 'allAuthenticatedUsers' from all project IAM bindings. "
                "If public access to a resource is required, restrict it to the resource level "
                "(e.g., a specific GCS bucket) rather than the project."
            ),
            evidence={"anonymous_bindings": violations}
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-07",
            check="No Anonymous or Public IAM Access",
            severity="Critical",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking for anonymous IAM access: {e}",
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
        "resource_type": "gcp_iam_policy",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/using-iam-securely#public_access",
            "https://cloud.google.com/storage/docs/access-control/making-data-public"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
