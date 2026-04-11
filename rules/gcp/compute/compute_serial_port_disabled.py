import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("compute", "v1", cache_discovery=False)

        # Check project-level serial port setting
        project_meta = service.projects().get(project=project_id).execute()
        common_meta = project_meta.get("commonInstanceMetadata", {})
        proj_meta_items = {
            item["key"]: item["value"]
            for item in common_meta.get("items", [])
        }
        proj_serial = proj_meta_items.get("serial-port-enable", "false").lower()
        project_serial_enabled = proj_serial in ("true", "1")

        findings.append(create_finding(
            "GCP-CMP-06", "Serial Port Disabled (Project Level)",
            "High" if project_serial_enabled else "Low",
            "FAIL" if project_serial_enabled else "PASS",
            project_id, f"projects/{project_id}", "global",
            "Serial port access is enabled at the project level — all instances may inherit this."
            if project_serial_enabled
            else "Serial port access is disabled at the project level.",
            "Set the 'serial-port-enable' project metadata key to 'false' to disable serial port "
            "access project-wide. Also enforce via org policy: "
            "'constraints/compute.disableSerialPortAccess'.",
            {"project_serial_port_enabled": project_serial_enabled}
        ))

        # Check each instance for serial port override
        agg = service.instances().aggregatedList(project=project_id).execute()
        for zone_data in agg.get("items", {}).values():
            for instance in zone_data.get("instances", []):
                instance_name = instance.get("name")
                zone = instance.get("zone", "").split("/")[-1]
                inst_meta_items = {
                    item["key"]: item["value"]
                    for item in instance.get("metadata", {}).get("items", [])
                }

                serial_val = inst_meta_items.get("serial-port-enable", "").lower()
                if serial_val == "":
                    # Inherits project setting
                    if project_serial_enabled:
                        findings.append(create_finding(
                            "GCP-CMP-06", "Serial Port Disabled (Instance Level)",
                            "High", "FAIL",
                            project_id, instance_name, zone,
                            f"Instance '{instance_name}' inherits serial port access from the "
                            "project level, which is enabled.",
                            "Explicitly disable serial port on this instance or disable it at "
                            "the project level.",
                            {"serial_port_enabled": True, "source": "inherited", "zone": zone}
                        ))
                    continue

                inst_serial_enabled = serial_val in ("true", "1")
                if inst_serial_enabled:
                    findings.append(create_finding(
                        "GCP-CMP-06", "Serial Port Disabled (Instance Level)",
                        "High", "FAIL",
                        project_id, instance_name, zone,
                        f"Instance '{instance_name}' has serial port access explicitly enabled.",
                        "Set the 'serial-port-enable' instance metadata key to 'false' and "
                        "remove any interactive serial port firewall rules.",
                        {"serial_port_enabled": True, "source": "instance_metadata", "zone": zone}
                    ))

    except Exception as e:
        findings.append(create_finding(
            "GCP-CMP-06", "Serial Port Disabled", "High", "ERROR",
            project_id, f"projects/{project_id}", "global",
            f"Error checking serial port configuration: {e}",
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
            "https://cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console",
            "https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
