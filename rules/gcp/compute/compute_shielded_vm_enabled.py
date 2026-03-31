import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("compute", "v1")
        agg = service.instances().aggregatedList(project=project_id).execute()
        items = agg.get("items", {})
    except Exception as e:
        return [create_finding(
            "GCP-CMP-02", "Shielded VM Enabled", "High", "ERROR",
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

            # All three components should be enabled for full Shielded VM coverage
            fully_shielded = vtpm_enabled and integrity_monitoring and secure_boot
            partially_shielded = any([vtpm_enabled, integrity_monitoring, secure_boot])

            if fully_shielded:
                status, severity = "PASS", "Low"
            elif partially_shielded:
                status, severity = "FAIL", "Medium"
            else:
                status, severity = "FAIL", "High"

            desc = (
                f"Instance '{instance_name}' has Shielded VM fully enabled "
                f"(Secure Boot={secure_boot}, vTPM={vtpm_enabled}, Integrity Monitoring={integrity_monitoring})."
                if fully_shielded
                else f"Instance '{instance_name}' has incomplete Shielded VM configuration — "
                     f"Secure Boot={secure_boot}, vTPM={vtpm_enabled}, Integrity Monitoring={integrity_monitoring}."
            )

            findings.append(create_finding(
                "GCP-CMP-02", "Shielded VM Enabled",
                severity, status, project_id, instance_name, zone, desc,
                "Enable all three Shielded VM components: Secure Boot, vTPM, and Integrity Monitoring. "
                "Stop the instance, edit the Shielded VM settings, then restart.",
                {
                    "secure_boot_enabled": secure_boot,
                    "vtpm_enabled": vtpm_enabled,
                    "integrity_monitoring_enabled": integrity_monitoring,
                    "zone": zone,
                    "machine_type": instance.get("machineType", "").split("/")[-1]
                }
            ))

    if instance_count == 0:
        findings.append(create_finding(
            "GCP-CMP-02", "Shielded VM Enabled", "Low", "PASS",
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
            "https://cloud.google.com/compute/docs/instances/modifying-shielded-vm",
            "https://cloud.google.com/security/products/shielded-vm"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
