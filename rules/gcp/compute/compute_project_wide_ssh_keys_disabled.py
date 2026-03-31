import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("compute", "v1")

        # Check whether any project-wide SSH keys exist
        project_meta = service.projects().get(project=project_id).execute()
        common_meta = project_meta.get("commonInstanceMetadata", {})
        proj_meta_items = {
            item["key"]: item["value"]
            for item in common_meta.get("items", [])
        }
        project_ssh_keys = proj_meta_items.get("ssh-keys", "").strip()
        has_project_ssh_keys = bool(project_ssh_keys)

        key_count = len([k for k in project_ssh_keys.splitlines() if k.strip()]) if has_project_ssh_keys else 0

        findings.append(create_finding(
            "GCP-CMP-07", "Project-Wide SSH Keys Disabled",
            "High" if has_project_ssh_keys else "Low",
            "FAIL" if has_project_ssh_keys else "PASS",
            project_id, f"projects/{project_id}", "global",
            f"Project has {key_count} project-wide SSH key(s) defined in common instance metadata. "
            "These keys grant SSH access to ALL instances in the project."
            if has_project_ssh_keys
            else "No project-wide SSH keys are defined in the project's common instance metadata.",
            "Remove all SSH keys from the project's common instance metadata. "
            "Use OS Login (IAM-controlled) for SSH access management instead.",
            {
                "project_wide_ssh_keys_present": has_project_ssh_keys,
                "key_count": key_count
            }
        ))

        # Check instances that block project-wide SSH keys (this is the desired state)
        # and instances that do NOT block them (at risk if project has keys)
        agg = service.instances().aggregatedList(project=project_id).execute()
        for zone_data in agg.get("items", {}).values():
            for instance in zone_data.get("instances", []):
                instance_name = instance.get("name")
                zone = instance.get("zone", "").split("/")[-1]
                inst_meta_items = {
                    item["key"]: item["value"]
                    for item in instance.get("metadata", {}).get("items", [])
                }

                blocks_project_keys = inst_meta_items.get(
                    "block-project-ssh-keys", "false"
                ).lower() == "true"

                # Only flag if project has SSH keys and the instance doesn't block them
                if has_project_ssh_keys and not blocks_project_keys:
                    findings.append(create_finding(
                        "GCP-CMP-07", "Project-Wide SSH Keys Disabled (Instance Level)",
                        "High", "FAIL",
                        project_id, instance_name, zone,
                        f"Instance '{instance_name}' does not block project-wide SSH keys "
                        "and inherits all SSH keys defined at the project level.",
                        "Set 'block-project-ssh-keys=true' in instance metadata, or remove "
                        "all SSH keys from the project's common instance metadata and use OS Login.",
                        {
                            "blocks_project_ssh_keys": blocks_project_keys,
                            "project_has_ssh_keys": has_project_ssh_keys,
                            "zone": zone
                        }
                    ))

    except Exception as e:
        findings.append(create_finding(
            "GCP-CMP-07", "Project-Wide SSH Keys Disabled", "High", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error checking project-wide SSH key configuration: {e}",
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
            "https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys#block-project-keys",
            "https://cloud.google.com/compute/docs/oslogin/set-up-oslogin"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
