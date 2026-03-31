import uuid

# IAP's IP range for TCP forwarding (SSH tunnels)
IAP_IP_RANGE = "35.235.240.0/20"

def run_check(credentials, project_id):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', credentials=credentials)
    findings = []

    firewalls = compute.firewalls().list(project=project_id).execute()
    items = firewalls.get('items', [])

    ssh_rules = []
    iap_ssh_rule_exists = False

    for fw in items:
        if fw.get('direction', 'INGRESS') != 'INGRESS':
            continue
        if fw.get('disabled', False):
            continue

        source_ranges = fw.get('sourceRanges', [])

        for rule in fw.get('allowed', []):
            ports = rule.get('ports', [])
            protocol = rule.get('IPProtocol', '')
            is_ssh_port = protocol == 'all' or (
                protocol == 'tcp' and any(p in ('22', '0-65535') for p in ports)
            )

            if not is_ssh_port:
                continue

            # Check if this rule is scoped to IAP's range only
            if source_ranges == [IAP_IP_RANGE]:
                iap_ssh_rule_exists = True
                ssh_rules.append({"name": fw['name'], "type": "iap", "source_ranges": source_ranges})
            elif '0.0.0.0/0' in source_ranges or '::/0' in source_ranges:
                ssh_rules.append({"name": fw['name'], "type": "open", "source_ranges": source_ranges})
            else:
                ssh_rules.append({"name": fw['name'], "type": "restricted", "source_ranges": source_ranges})

    open_ssh_rules = [r for r in ssh_rules if r['type'] == 'open']
    iap_enforced = iap_ssh_rule_exists and len(open_ssh_rules) == 0

    status = "PASS" if iap_enforced else "FAIL"
    severity = "Low" if iap_enforced else ("Critical" if open_ssh_rules else "Medium")

    if iap_enforced:
        desc = "SSH access is gated through IAP only; no open SSH firewall rules found."
        rem = "No action required."
    elif open_ssh_rules:
        names = ', '.join(r['name'] for r in open_ssh_rules)
        desc = f"SSH is open to the internet via firewall rule(s): {names}. IAP is not being used."
        rem = "Remove open SSH firewall rules and configure an IAP-scoped rule (source: 35.235.240.0/20) instead."
    else:
        desc = "No IAP-scoped SSH rule found. SSH access may be unavailable or incorrectly configured."
        rem = "Create a firewall rule allowing TCP port 22 from 35.235.240.0/20 to enable IAP-based SSH."

    findings.append(create_finding(
        "GCP-VPC-10",
        "IAP Used for SSH Access",
        severity,
        status,
        f"projects/{project_id}/global/firewalls",
        desc,
        rem,
        {"iap_ssh_rule_exists": iap_ssh_rule_exists, "open_ssh_rules": open_ssh_rules,
         "all_ssh_rules": ssh_rules}
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
        "resource_type": "gcp_compute_firewall",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/iap/docs/using-tcp-forwarding",
            "https://cloud.google.com/vpc/docs/firewalls"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
