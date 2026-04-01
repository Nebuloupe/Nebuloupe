import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        open_rdp = False

        for rule in sg['IpPermissions']:
            if rule.get('FromPort') == 3389:
                for ip in rule.get('IpRanges', []):
                    if ip['CidrIp'] == '0.0.0.0/0':
                        open_rdp = True

        findings.append(create_finding(
            "VPC-02",
            "Security Group RDP Open",
            "Critical" if open_rdp else "Low",
            "FAIL" if open_rdp else "PASS",
            sg['GroupId'],
            "RDP open to internet." if open_rdp else "RDP not open publicly.",
            "Restrict RDP access." if open_rdp else "No action required.",
            {"rules": sg['IpPermissions']}
        ))

    return findings
def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "Networking",
        "resource_type": "aws_security_group",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [],
        "resource_attributes": {},
        "evidence": evidence
    }