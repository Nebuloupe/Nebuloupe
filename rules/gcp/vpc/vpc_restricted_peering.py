import uuid

def run_check(credentials, project_id):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', credentials=credentials)
    findings = []

    networks_resp = compute.networks().list(project=project_id).execute()
    networks = networks_resp.get('items', [])

    for network in networks:
        peerings = network.get('peerings', [])

        if not peerings:
            # No peering configured — nothing to flag
            continue

        for peering in peerings:
            peer_network_url = peering.get('network', '')
            peer_network_name = peer_network_url.split('/')[-1]
            peer_project = ''

            # Extract peer project from URL: .../projects/<proj>/global/networks/<name>
            parts = peer_network_url.split('/')
            if 'projects' in parts:
                idx = parts.index('projects')
                peer_project = parts[idx + 1] if idx + 1 < len(parts) else ''

            is_cross_project = peer_project != project_id
            is_active = peering.get('state') == 'ACTIVE'

            # Flag cross-project peerings as needing review; inactive peerings are also flagged
            risky = is_cross_project or not is_active

            findings.append(create_finding(
                "GCP-VPC-08",
                "VPC Peering Restricted",
                "Medium" if risky else "Low",
                "FAIL" if risky else "PASS",
                network['selfLink'],
                f"Network '{network['name']}' has a peering to '{peer_network_name}' in project '{peer_project}' "
                f"({'active' if is_active else 'inactive'})." if risky
                else f"Network '{network['name']}' peering to '{peer_network_name}' appears secure.",
                "Review VPC peering connections. Remove stale or unintended cross-project peerings." if risky
                else "No action required.",
                {
                    "network": network['name'],
                    "peer_network": peer_network_name,
                    "peer_project": peer_project,
                    "cross_project": is_cross_project,
                    "state": peering.get('state')
                }
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
            "https://cloud.google.com/vpc/docs/vpc-peering"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
