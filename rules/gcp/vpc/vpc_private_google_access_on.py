import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', cache_discovery=False)
    findings = []

    subnets_resp = compute.subnetworks().aggregatedList(project=project_id).execute()
    items = subnets_resp.get('items', {})

    for region_key, region_data in items.items():
        for subnet in region_data.get('subnetworks', []):
            pga_enabled = subnet.get('privateIpGoogleAccess', False)
            subnet_name = subnet['name']
            region = subnet.get('region', '').split('/')[-1]

            findings.append(create_finding(
                "GCP-VPC-04",
                "Private Google Access Enabled on Subnet",
                "Medium" if not pga_enabled else "Low",
                "FAIL" if not pga_enabled else "PASS",
                project_id,
                subnet['selfLink'],
                f"Subnet '{subnet_name}' does not have Private Google Access enabled." if not pga_enabled
                else f"Subnet '{subnet_name}' has Private Google Access enabled.",
                "Enable Private Google Access so VMs without external IPs can reach Google APIs." if not pga_enabled
                else "No action required.",
                {"subnet": subnet_name, "region": region, "private_google_access": pga_enabled}
            ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "project_id": project_id,
        "cloud_provider": "gcp",
        "category": "Networking",
        "resource_type": "gcp_compute_subnetwork",
        "resource_id": res_id,
        "region": evidence.get("region", "global"),
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/vpc/docs/private-google-access"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
