import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1')
    findings = []

    firewalls = compute.firewalls().list(project=project_id).execute()
    items = firewalls.get('items', [])

    for fw in items:
        if fw.get('direction', 'INGRESS') != 'INGRESS':
            continue
        if fw.get('disabled', False):
            continue

        ssh_open = False
        source_ranges = fw.get('sourceRanges', [])
        open_to_all = '0.0.0.0/0' in source_ranges or '::/0' in source_ranges

        if open_to_all:
            for rule in fw.get('allowed', []):
                ports = rule.get('ports', [])
                protocol = rule.get('IPProtocol', '')
                if protocol == 'all':
                    ssh_open = True
                elif protocol == 'tcp':
                    for p in ports:
                        if p == '22' or p == '0-65535':
                            ssh_open = True

        findings.append(create_finding(
            "GCP-VPC-02",
            "Firewall Rule SSH Open to Internet",
            "Critical" if ssh_open else "Low",
            "FAIL" if ssh_open else "PASS",
            project_id,
            fw['selfLink'],
            f"Firewall rule '{fw['name']}' allows SSH (port 22) from 0.0.0.0/0." if ssh_open
            else f"Firewall rule '{fw['name']}' does not expose SSH publicly.",
            "Restrict SSH firewall rule to known IP ranges or use IAP for SSH access." if ssh_open
            else "No action required.",
            {"firewall_name": fw['name'], "source_ranges": source_ranges, "allowed": fw.get('allowed', [])}
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
