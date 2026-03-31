import uuid

def run_check(credentials, project_id):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', credentials=credentials)
    findings = []

    firewalls = compute.firewalls().list(project=project_id).execute()
    items = firewalls.get('items', [])

    for fw in items:
        if fw.get('direction', 'INGRESS') != 'INGRESS':
            continue
        if fw.get('disabled', False):
            continue

        rdp_open = False
        source_ranges = fw.get('sourceRanges', [])
        open_to_all = '0.0.0.0/0' in source_ranges or '::/0' in source_ranges

        if open_to_all:
            for rule in fw.get('allowed', []):
                ports = rule.get('ports', [])
                protocol = rule.get('IPProtocol', '')
                if protocol == 'all':
                    rdp_open = True
                elif protocol == 'tcp':
                    for p in ports:
                        if p == '3389' or p == '0-65535':
                            rdp_open = True

        findings.append(create_finding(
            "GCP-VPC-03",
            "Firewall Rule RDP Open to Internet",
            "Critical" if rdp_open else "Low",
            "FAIL" if rdp_open else "PASS",
            fw['selfLink'],
            f"Firewall rule '{fw['name']}' allows RDP (port 3389) from 0.0.0.0/0." if rdp_open
            else f"Firewall rule '{fw['name']}' does not expose RDP publicly.",
            "Restrict RDP firewall rule to known IP ranges or use IAP for remote access." if rdp_open
            else "No action required.",
            {"firewall_name": fw['name'], "source_ranges": source_ranges, "allowed": fw.get('allowed', [])}
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
            "https://cloud.google.com/vpc/docs/firewalls",
            "https://cloud.google.com/iap/docs/using-tcp-forwarding"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
