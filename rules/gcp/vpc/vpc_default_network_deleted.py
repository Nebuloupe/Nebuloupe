import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', cache_discovery=False)
    findings = []

    networks = compute.networks().list(project=project_id).execute()
    items = networks.get('items', [])

    default_exists = any(n['name'] == 'default' for n in items)

    findings.append(create_finding(
        "GCP-VPC-01",
        "Default VPC Network Deleted",
        "High" if default_exists else "Low",
        "FAIL" if default_exists else "PASS",
        f"projects/{project_id}/global/networks/default",
        "Default VPC network still exists in project." if default_exists else "Default VPC network has been deleted.",
        "Delete the default VPC network to reduce attack surface." if default_exists else "No action required.",
        {"default_network_present": default_exists}
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
        "resource_type": "gcp_compute_network",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/vpc/docs/vpc#default-network"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
