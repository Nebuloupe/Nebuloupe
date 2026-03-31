import uuid

def run_check(credentials, project_id):
    from googleapiclient import discovery

    dns = discovery.build('dns', 'v1', credentials=credentials)
    compute = discovery.build('compute', 'v1', credentials=credentials)
    findings = []

    # Get all VPC networks
    networks_resp = compute.networks().list(project=project_id).execute()
    networks = networks_resp.get('items', [])

    # Get DNS policies and map them to networks
    policies_resp = dns.policies().list(project=project_id).execute()
    policies = policies_resp.get('policies', [])

    # Build a map: network selfLink -> dns logging enabled
    network_logging = {}
    for policy in policies:
        logging_enabled = policy.get('enableLogging', False)
        for net in policy.get('networks', []):
            network_logging[net['networkUrl']] = logging_enabled

    for network in networks:
        net_url = network['selfLink']
        has_policy = net_url in network_logging
        logging_enabled = network_logging.get(net_url, False)
        dns_logging_on = has_policy and logging_enabled

        findings.append(create_finding(
            "GCP-VPC-07",
            "DNS Logging Enabled on VPC Network",
            "Medium" if not dns_logging_on else "Low",
            "FAIL" if not dns_logging_on else "PASS",
            net_url,
            f"Network '{network['name']}' does not have DNS logging enabled." if not dns_logging_on
            else f"Network '{network['name']}' has DNS logging enabled.",
            "Create or update a DNS policy to enable DNS logging for this VPC network." if not dns_logging_on
            else "No action required.",
            {"network_name": network['name'], "dns_policy_attached": has_policy,
             "dns_logging_enabled": dns_logging_on}
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
            "https://cloud.google.com/dns/docs/monitoring"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
