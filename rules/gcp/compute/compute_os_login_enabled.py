import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("compute", "v1", cache_discovery=False)

        # Check project-level OS Login metadata
        project_meta = service.projects().get(project=project_id).execute()
        common_meta = project_meta.get("commonInstanceMetadata", {})
        meta_items = {
            item["key"]: item["value"]
            for item in common_meta.get("items", [])
        }
        project_os_login = meta_items.get("enable-oslogin", "false").lower() == "true"

        findings.append(create_finding(
            "GCP-CMP-03", "OS Login Enabled (Project Level)",
            "Low" if project_os_login else "High",
            "PASS" if project_os_login else "FAIL",
            project_id, f"projects/{project_id}", "global",
            "OS Login is enabled at the project level — all instances inherit this default."
            if project_os_login
            else "OS Login is NOT enabled at the project level. SSH key management falls back "
                 "to metadata-based keys, which are harder to audit and revoke.",
            "Set metadata key 'enable-oslogin' to 'true' in the project's common instance metadata "
            "to enforce OS Login across all instances by default.",
            {"project_os_login_enabled": project_os_login}
        ))

        # Check each instance for explicit overrides
        agg = service.instances().aggregatedList(project=project_id).execute()
        for zone_data in agg.get("items", {}).values():
            for instance in zone_data.get("instances", []):
                instance_name = instance.get("name")
                zone = instance.get("zone", "").split("/")[-1]
                inst_meta_items = {
                    item["key"]: item["value"]
                    for item in instance.get("metadata", {}).get("items", [])
                }

                if "enable-oslogin" not in inst_meta_items:
                    # Inherits project setting — only flag if project is also not set
                    if not project_os_login:
                        findings.append(create_finding(
                            "GCP-CMP-03", "OS Login Enabled (Instance Level)",
                            "High", "FAIL",
                            project_id, instance_name, zone,
                            f"Instance '{instance_name}' does not set OS Login and inherits "
                            "the project-level setting, which is disabled.",
                            "Enable OS Login at the project level or explicitly set "
                            "'enable-oslogin=true' on the instance metadata.",
                            {"instance_os_login": None, "inherits_project": True, "zone": zone}
                        ))
                    continue

                inst_os_login = inst_meta_items["enable-oslogin"].lower() == "true"
                if not inst_os_login:
                    findings.append(create_finding(
                        "GCP-CMP-03", "OS Login Enabled (Instance Level)",
                        "High", "FAIL",
                        project_id, instance_name, zone,
                        f"Instance '{instance_name}' explicitly disables OS Login via instance metadata, "
                        "overriding any project-level setting.",
                        "Remove the 'enable-oslogin=false' metadata override or set it to 'true' "
                        "to enforce IAM-controlled SSH access.",
                        {"instance_os_login": inst_os_login, "zone": zone}
                    ))

    except Exception as e:
        findings.append(create_finding(
            "GCP-CMP-03", "OS Login Enabled", "High", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error checking OS Login configuration: {e}",
            "Ensure compute.googleapis.com is enabled and caller has compute.projects.get "
            "and compute.instances.list permissions.",
            {"error": str(e)}
        ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, region, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Compute",
        "resource_type": "gcp_compute_instance",
        "resource_id": res_id,
        "project_id": project_id,
        "region": region,
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/compute/docs/oslogin/set-up-oslogin",
            "https://cloud.google.com/compute/docs/instances/managing-instance-access"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
