import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from collections import defaultdict


# Role pairs that should not be held by the same principal (separation of duties)
CONFLICTING_ROLE_PAIRS = [
    ("roles/iam.securityAdmin", "roles/iam.serviceAccountAdmin"),
    ("roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountUser"),
    ("roles/cloudbuild.builds.editor", "roles/storage.admin"),
    ("roles/owner", "roles/iam.serviceAccountTokenCreator"),
    ("roles/editor", "roles/iam.serviceAccountTokenCreator"),
]


def run_check(project_id: str):
    findings = []
    violations = []

    try:
        client = resourcemanager_v3.ProjectsClient()
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = client.get_iam_policy(request=request)

        # Build a map: member -> set of roles
        member_roles = defaultdict(set)
        for binding in policy.bindings:
            for member in binding.members:
                member_roles[member].add(binding.role)

        # Check for conflicting role combinations per principal
        for member, roles in member_roles.items():
            for role_a, role_b in CONFLICTING_ROLE_PAIRS:
                if role_a in roles and role_b in roles:
                    violations.append({
                        "member": member,
                        "conflicting_roles": [role_a, role_b]
                    })

        status = "FAIL" if violations else "PASS"
        desc = (
            f"{len(violations)} principal(s) hold conflicting role combinations "
            "that violate separation of duties."
            if violations
            else "No separation-of-duties violations detected in project IAM bindings."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-06",
            check="IAM Separation of Duties",
            severity="High",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Remove conflicting role combinations from individual principals. "
                "Assign privileged roles to separate identities and enforce least privilege "
                "to ensure no single principal can perform both sensitive operations."
            ),
            evidence={
                "checked_conflicting_pairs": CONFLICTING_ROLE_PAIRS,
                "violations": violations
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-06",
            check="IAM Separation of Duties",
            severity="High",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking separation of duties: {e}",
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
            "https://cloud.google.com/iam/docs/using-iam-securely#separation-of-duties",
            "https://cloud.google.com/iam/docs/understanding-roles"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
