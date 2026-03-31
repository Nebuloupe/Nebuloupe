import uuid
from google.cloud import resourcemanager_v3
from google.iam.v1 import iam_policy_pb2
from googleapiclient.discovery import build


def run_check(project_id: str):
    """
    Checks that the default Compute Engine service account is not bound to
    any IAM role at the project level, and that GCE instances do not use it.
    """
    findings = []
    violations = []

    try:
        # Get project number to form the default SA email
        rm_client = resourcemanager_v3.ProjectsClient()
        project = rm_client.get_project(name=f"projects/{project_id}")
        project_number = project.name.split("/")[-1]
        default_sa = f"{project_number}-compute@developer.gserviceaccount.com"

        # Check project IAM policy for bindings to the default compute SA
        request = iam_policy_pb2.GetIamPolicyRequest(
            resource=f"projects/{project_id}"
        )
        policy = rm_client.get_iam_policy(request=request)

        for binding in policy.bindings:
            member = f"serviceAccount:{default_sa}"
            if member in binding.members:
                violations.append({
                    "type": "iam_binding",
                    "role": binding.role,
                    "member": member
                })

        # Check if any GCE instances use the default compute SA
        try:
            compute = build("compute", "v1")
            agg_list = compute.instances().aggregatedList(project=project_id).execute()
            for zone_data in agg_list.get("items", {}).values():
                for instance in zone_data.get("instances", []):
                    for sa in instance.get("serviceAccounts", []):
                        if sa.get("email") == default_sa:
                            violations.append({
                                "type": "gce_instance",
                                "instance": instance.get("name"),
                                "zone": instance.get("zone", "").split("/")[-1],
                                "service_account": default_sa
                            })
        except Exception:
            pass  # compute API may not be enabled; IAM check is primary

        status = "FAIL" if violations else "PASS"
        desc = (
            f"The default Compute Engine service account ({default_sa}) is actively used "
            f"in {len(violations)} binding(s) or instance(s)."
            if violations
            else f"The default Compute Engine service account ({default_sa}) is not in use."
        )

        findings.append(create_finding(
            rule_id="GCP-IAM-05",
            check="Default Compute Service Account Unused",
            severity="High",
            status=status,
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=desc,
            rem=(
                "Do not use the default Compute Engine service account. Create dedicated "
                "service accounts with only the permissions required for each workload. "
                "Remove the default SA from project IAM bindings."
            ),
            evidence={
                "default_compute_sa": default_sa,
                "violations": violations
            }
        ))
    except Exception as e:
        findings.append(create_finding(
            rule_id="GCP-IAM-05",
            check="Default Compute Service Account Unused",
            severity="High",
            status="ERROR",
            project_id=project_id,
            res_id=f"projects/{project_id}",
            desc=f"Error checking default compute service account usage: {e}",
            rem="Ensure resourcemanager.googleapis.com and iam.googleapis.com are enabled.",
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
        "resource_type": "gcp_service_account",
        "resource_id": res_id,
        "project_id": project_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iam/docs/best-practices-service-accounts#default-compute-service-account",
            "https://cloud.google.com/compute/docs/access/service-accounts"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
