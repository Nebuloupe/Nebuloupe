import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', cache_discovery=False)

    subnets_resp = compute.subnetworks().aggregatedList(project=project_id).execute()
    items = subnets_resp.get('items', {})
    total_subnets = 0
    non_compliant = []

    for region_key, region_data in items.items():
        for subnet in region_data.get('subnetworks', []):
            total_subnets += 1
            log_config = subnet.get('logConfig', {})
            flow_logs_enabled = log_config.get('enable', False)
            subnet_name = subnet['name']
            region = subnet.get('region', '').split('/')[-1]
            if not flow_logs_enabled:
                non_compliant.append({
                    "subnet": subnet_name,
                    "region": region,
                    "resource_id": subnet.get('selfLink', subnet_name)
                })

    fail_count = len(non_compliant)
    sample = non_compliant[:20]

    return [create_finding(
        "GCP-VPC-05",
        "VPC Flow Logs Enabled on Subnet",
        "Medium" if fail_count else "Low",
        "FAIL" if fail_count else "PASS",
        project_id,
        f"projects/{project_id}",
        f"{fail_count} of {total_subnets} subnet(s) do not have VPC flow logs enabled."
        if fail_count else
        f"All {total_subnets} subnet(s) have VPC flow logs enabled.",
        "Enable VPC flow logs on affected subnets for network monitoring and forensics."
        if fail_count else
        "No action required.",
        {
            "total_subnets": total_subnets,
            "non_compliant_count": fail_count,
            "non_compliant_subnets_sample": sample
        }
    )]


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
