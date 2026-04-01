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
            "GCP-CMP-01", "Compute VM No Public IP", "High", "ERROR",
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
            network_interfaces = instance.get("networkInterfaces", [])

            public_ips = []
            for nic in network_interfaces:
                for access_config in nic.get("accessConfigs", []):
                    nat_ip = access_config.get("natIP")
                    if nat_ip:
                        public_ips.append({
                            "interface": nic.get("name"),
                            "nat_ip": nat_ip,
                            "access_config_name": access_config.get("name")
                        })

            has_public_ip = bool(public_ips)
            status = "FAIL" if has_public_ip else "PASS"
            desc = (
                f"Instance '{instance_name}' has {len(public_ips)} public IP(s) assigned: "
                f"{[p['nat_ip'] for p in public_ips]}."
                if has_public_ip
                else f"Instance '{instance_name}' has no public IP addresses."
            )

            findings.append(create_finding(
                "GCP-CMP-01", "Compute VM No Public IP",
                "High" if has_public_ip else "Low",
                status, project_id, instance_name, zone, desc,
                "Remove external IP addresses from VM instances. Use Cloud NAT for outbound "
                "internet access and Identity-Aware Proxy (IAP) or a bastion host for SSH/RDP.",
                {
                    "public_ips": public_ips,
                    "zone": zone,
                    "machine_type": instance.get("machineType", "").split("/")[-1],
                    "status": instance.get("status")
                }
            ))

    if instance_count == 0:
        findings.append(create_finding(
            "GCP-CMP-01", "Compute VM No Public IP", "Low", "PASS",
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
            "https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address",
            "https://cloud.google.com/nat/docs/overview"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
