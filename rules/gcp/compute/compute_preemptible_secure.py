import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    """
    Checks that preemptible/Spot VMs meet the same security baseline as
    regular instances: Shielded VM, no public IP, OS Login, no serial port.
    Preemptible instances are often overlooked in security reviews because
    of their transient nature.
    """
    findings = []

    try:
        service = build("compute", "v1")
        agg = service.instances().aggregatedList(project=project_id).execute()
        items = agg.get("items", {})
    except Exception as e:
        return [create_finding(
            "GCP-CMP-05", "Preemptible VM Secure Configuration", "Medium", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error listing Compute instances: {e}",
            "Ensure compute.googleapis.com is enabled and caller has compute.instances.list permission.",
            {"error": str(e)}
        )]

    preemptible_count = 0
    for zone_data in items.values():
        for instance in zone_data.get("instances", []):
            scheduling = instance.get("scheduling", {})
            is_preemptible = scheduling.get("preemptible", False)
            # Spot VMs use onHostMaintenance=TERMINATE + automaticRestart=False (no preemptible flag)
            is_spot = (
                scheduling.get("provisioningModel", "") == "SPOT"
                or (
                    scheduling.get("onHostMaintenance") == "TERMINATE"
                    and scheduling.get("automaticRestart") is False
                    and not is_preemptible
                )
            )

            if not (is_preemptible or is_spot):
                continue

            preemptible_count += 1
            instance_name = instance.get("name")
            zone = instance.get("zone", "").split("/")[-1]
            issues = []

            # Check 1: Public IP
            for nic in instance.get("networkInterfaces", []):
                for ac in nic.get("accessConfigs", []):
                    if ac.get("natIP"):
                        issues.append(f"Has public IP: {ac['natIP']}")

            # Check 2: Shielded VM
            shielded = instance.get("shieldedInstanceConfig", {})
            if not (shielded.get("enableVtpm") and shielded.get("enableIntegrityMonitoring")):
                issues.append("Shielded VM (vTPM + Integrity Monitoring) not fully enabled")

            # Check 3: Serial port
            meta_items = {
                item["key"]: item["value"]
                for item in instance.get("metadata", {}).get("items", [])
            }
            if meta_items.get("serial-port-enable", "false").lower() in ("true", "1"):
                issues.append("Serial port access is enabled")

            # Check 4: OS Login override
            if meta_items.get("enable-oslogin", "").lower() == "false":
                issues.append("OS Login explicitly disabled on instance")

            status = "FAIL" if issues else "PASS"
            vm_type = "Spot" if is_spot else "Preemptible"
            desc = (
                f"{vm_type} instance '{instance_name}' has {len(issues)} security issue(s): "
                + "; ".join(issues)
                if issues
                else f"{vm_type} instance '{instance_name}' meets the security baseline."
            )

            findings.append(create_finding(
                "GCP-CMP-05", "Preemptible VM Secure Configuration",
                "Medium" if issues else "Low",
                status, project_id, instance_name, zone, desc,
                "Apply the same security controls to preemptible/Spot VMs as standard instances: "
                "remove public IPs, enable Shielded VM, disable serial port, and enforce OS Login.",
                {
                    "vm_type": vm_type,
                    "issues": issues,
                    "zone": zone,
                    "machine_type": instance.get("machineType", "").split("/")[-1]
                }
            ))

    if preemptible_count == 0:
        findings.append(create_finding(
            "GCP-CMP-05", "Preemptible VM Secure Configuration", "Low", "PASS",
            project_id, f"projects/{project_id}", "global",
            "No preemptible or Spot VM instances found in this project.",
            "No action required.", {"preemptible_count": 0}
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
            "https://cloud.google.com/compute/docs/instances/preemptible",
            "https://cloud.google.com/compute/docs/instances/spot"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
