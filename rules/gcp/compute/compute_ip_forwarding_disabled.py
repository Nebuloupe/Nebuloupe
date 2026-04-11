import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("compute", "v1", cache_discovery=False)
        agg = service.instances().aggregatedList(project=project_id).execute()
        items = agg.get("items", {})
    except Exception as e:
        return [create_finding(
            "GCP-CMP-04", "Compute IP Forwarding Disabled", "Medium", "ERROR",
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

            # canIpForward=True means the instance can forward packets not addressed to it
            ip_forwarding = instance.get("canIpForward", False)
            status = "FAIL" if ip_forwarding else "PASS"

            desc = (
                f"Instance '{instance_name}' has IP forwarding enabled. "
                "It can route or forward packets not destined for its own IP addresses."
                if ip_forwarding
                else f"Instance '{instance_name}' has IP forwarding disabled."
            )

            findings.append(create_finding(
                "GCP-CMP-04", "Compute IP Forwarding Disabled",
                "Medium" if ip_forwarding else "Low",
                status, project_id, instance_name, zone, desc,
                "Disable IP forwarding on instances that are not intentionally acting as "
                "network appliances or routers. Create a new instance with 'canIpForward=false' "
                "if the setting cannot be changed in-place.",
                {
                    "ip_forwarding_enabled": ip_forwarding,
                    "zone": zone,
                    "machine_type": instance.get("machineType", "").split("/")[-1]
                }
            ))

    if instance_count == 0:
        findings.append(create_finding(
            "GCP-CMP-04", "Compute IP Forwarding Disabled", "Low", "PASS",
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
            "https://cloud.google.com/compute/docs/networking/using-ip-forwarding",
            "https://cloud.google.com/compute/docs/reference/rest/v1/instances"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
