import uuid

def run_check(credentials, project_id):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', credentials=credentials)
    findings = []

    networks = compute.networks().list(project=project_id).execute()
    items = networks.get('items', [])

    for network in items:
        # Legacy networks do not have subnetworkMode; auto/custom mode networks do
        is_legacy = 'subnetworkMode' not in network and network.get('IPv4Range') is not None

        findings.append(create_finding(
            "GCP-VPC-06",
            "Legacy VPC Network Absent",
            "High" if is_legacy else "Low",
            "FAIL" if is_legacy else "PASS",
            network['selfLink'],
            f"Network '{network['name']}' is a legacy (non-subnet-mode) network." if is_legacy
            else f"Network '{network['name']}' is a modern subnet-mode network.",
            "Migrate away from legacy networks and use custom-mode VPC networks." if is_legacy
            else "No action required.",
            {"network_name": network['name'], "is_legacy": is_legacy,
             "ipv4_range": network.get('IPv4Range', None)}
        ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Networking",
        "resource_type": "gcp_compute_network",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/vpc/docs/legacy"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
