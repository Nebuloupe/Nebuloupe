import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    """
    Checks that all Compute Engine instances have the virtual Trusted Platform
    Module (vTPM) enabled as part of the Shielded VM configuration.

    vTPM enables:
    - Measured Boot for integrity verification
    - Generation of keys attestable to the virtual hardware
    - A root of trust for Shielded VM integrity monitoring

    This check is more granular than the broader Shielded VM check and
    specifically isolates the vTPM component for compliance reporting.
    """
    findings = []

    try:
        service = build("compute", "v1", cache_discovery=False)
        agg = service.instances().aggregatedList(project=project_id).execute()
        items = agg.get("items", {})
    except Exception as e:
        return [create_finding(
            "GCP-CMP-10", "vTPM Enabled on Shielded VM", "Medium", "ERROR",
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

            shielded_config = instance.get("shieldedInstanceConfig", {})
            vtpm_enabled = shielded_config.get("enableVtpm", False)
            integrity_monitoring = shielded_config.get("enableIntegrityMonitoring", False)
            secure_boot = shielded_config.get("enableSecureBoot", False)

            status = "PASS" if vtpm_enabled else "FAIL"
            desc = (
                f"Instance '{instance_name}' has vTPM enabled "
                f"(Integrity Monitoring={integrity_monitoring}, Secure Boot={secure_boot})."
                if vtpm_enabled
                else f"Instance '{instance_name}' does not have vTPM enabled. "
                     "Integrity monitoring and measured boot are unavailable without vTPM."
            )

            findings.append(create_finding(
                "GCP-CMP-10", "vTPM Enabled on Shielded VM",
                "Low" if vtpm_enabled else "Medium",
                status, project_id, instance_name, zone, desc,
                "Enable vTPM in the Shielded VM configuration. Stop the instance, navigate to "
                "VM details > Edit > Shielded VM, enable 'vTPM', then restart. "
                "Also enable Integrity Monitoring and Secure Boot for complete Shielded VM coverage.",
                {
                    "vtpm_enabled": vtpm_enabled,
                    "integrity_monitoring_enabled": integrity_monitoring,
                    "secure_boot_enabled": secure_boot,
                    "zone": zone,
                    "machine_type": instance.get("machineType", "").split("/")[-1]
                }
            ))

    if instance_count == 0:
        findings.append(create_finding(
            "GCP-CMP-10", "vTPM Enabled on Shielded VM", "Low", "PASS",
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
            "https://cloud.google.com/compute/shielded-vm/docs/shielded-vm#vtpm",
            "https://cloud.google.com/compute/docs/instances/modifying-shielded-vm"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
