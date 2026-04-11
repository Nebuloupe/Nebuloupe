import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', cache_discovery=False)
    findings = []

    subnets_resp = compute.subnetworks().aggregatedList(project=project_id).execute()
    items = subnets_resp.get('items', {})

    for region_key, region_data in items.items():
        for subnet in region_data.get('subnetworks', []):
            log_config = subnet.get('logConfig', {})
            flow_logs_enabled = log_config.get('enable', False)
            subnet_name = subnet['name']
            region = subnet.get('region', '').split('/')[-1]

            findings.append(create_finding(
                "GCP-VPC-05",
                "VPC Flow Logs Enabled on Subnet",
                "Medium" if not flow_logs_enabled else "Low",
                "FAIL" if not flow_logs_enabled else "PASS",
                project_id,
                subnet['selfLink'],
                f"Subnet '{subnet_name}' does not have VPC flow logs enabled." if not flow_logs_enabled
                else f"Subnet '{subnet_name}' has VPC flow logs enabled.",
                "Enable VPC flow logs on subnet for network monitoring and forensics." if not flow_logs_enabled
                else "No action required.",
                {"subnet": subnet_name, "region": region, "flow_logs_enabled": flow_logs_enabled}
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
            "https://cloud.google.com/vpc/docs/using-flow-logs"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
