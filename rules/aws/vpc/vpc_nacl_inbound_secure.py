import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    nacls = ec2.describe_network_acls()['NetworkAcls']

    for acl in nacls:
        insecure = False

        for entry in acl['Entries']:
            if entry['Egress'] is False and entry['CidrBlock'] == '0.0.0.0/0':
                if entry['RuleAction'] == 'allow':
                    insecure = True

        findings.append(create_finding(
            "VPC-08",
            "NACL Inbound Secure",
            "High" if insecure else "Low",
            "FAIL" if insecure else "PASS",
            acl['NetworkAclId'],
            "Inbound rule allows all traffic." if insecure else "Inbound rules secure.",
            "Restrict NACL inbound rules." if insecure else "No action required.",
            {"entries": acl['Entries']}
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