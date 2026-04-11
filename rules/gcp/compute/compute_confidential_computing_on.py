import uuid
from googleapiclient.discovery import build


# Machine type families that support Confidential Computing
CONFIDENTIAL_SUPPORTED_PREFIXES = ("n2d-", "c2d-", "n2-", "c3-")


def run_check(project_id: str):
    """
    Checks that Confidential Computing (Confidential VM) is enabled on
    applicable instances. Confidential VMs encrypt data in-use using AMD SEV
    or Intel TDX, providing hardware-level memory encryption.

    Instances on non-supporting machine type families are reported as
    informational PASS since Confidential Computing cannot be enabled on them.
    """
    findings = []

    try:
        service = build("compute", "v1", cache_discovery=False)
        agg = service.instances().aggregatedList(project=project_id).execute()
        items = agg.get("items", {})
    except Exception as e:
        return [create_finding(
            "GCP-CMP-09", "Confidential Computing Enabled", "High", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error listing Compute instances: {e}",
            "Ensure compute.googleapis.com is enabled and caller has compute.instances.list permission.",
            {"error": str(e)}
        )]

    instance_count = 0
    for zone_data in items.values():
        for instance in zone_data.get("instances", []):
            instance_count += 1
            instance_name = instance.get("name")
            zone = instance.get("zone", "").split("/")[-1]
            machine_type = instance.get("machineType", "").split("/")[-1]

            confidential_config = instance.get("confidentialInstanceConfig", {})
            confidential_enabled = confidential_config.get("enableConfidentialCompute", False)
            confidential_type = confidential_config.get("confidentialInstanceType", "")

            # Check if the machine type supports Confidential Computing
            supports_confidential = any(
                machine_type.startswith(prefix) for prefix in CONFIDENTIAL_SUPPORTED_PREFIXES
            )

            if not supports_confidential:
                findings.append(create_finding(
                    "GCP-CMP-09", "Confidential Computing Enabled",
                    "Low", "PASS",
                    project_id, instance_name, zone,
                    f"Instance '{instance_name}' uses machine type '{machine_type}' which does not "
                    "support Confidential Computing — check is not applicable.",
                    "To use Confidential Computing, create a new instance on a supported machine "
                    f"type (e.g., {', '.join(CONFIDENTIAL_SUPPORTED_PREFIXES)}).",
                    {
                        "machine_type": machine_type,
                        "supports_confidential": False,
                        "confidential_enabled": False,
                        "zone": zone
                    }
                ))
                continue

            status = "PASS" if confidential_enabled else "FAIL"
            desc = (
                f"Instance '{instance_name}' has Confidential Computing enabled "
                f"(type='{confidential_type or 'SEV'}')."
                if confidential_enabled
                else f"Instance '{instance_name}' supports Confidential Computing "
                     f"(machine type: '{machine_type}') but it is not enabled."
            )

            findings.append(create_finding(
                "GCP-CMP-09", "Confidential Computing Enabled",
                "Low" if confidential_enabled else "High",
                status, project_id, instance_name, zone, desc,
                "Enable Confidential Computing when creating instances on supported machine types. "
                "Note: Confidential VM cannot be enabled on existing instances — a new instance "
                "must be created with the 'confidentialInstanceConfig.enableConfidentialCompute=true' flag.",
                {
                    "confidential_enabled": confidential_enabled,
                    "confidential_type": confidential_type or None,
                    "machine_type": machine_type,
                    "supports_confidential": supports_confidential,
                    "zone": zone
                }
            ))

    if instance_count == 0:
        findings.append(create_finding(
            "GCP-CMP-09", "Confidential Computing Enabled", "Low", "PASS",
            project_id, f"projects/{project_id}", "global",
            "No Compute Engine instances found in this project.",
            "No action required.", {"instance_count": 0}
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
            "https://cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview",
            "https://cloud.google.com/compute/docs/instances/create-start-instance#create_a_vm_instance_with_confidential_vm_service"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
