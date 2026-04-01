import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    peerings = ec2.describe_vpc_peering_connections()['VpcPeeringConnections']

    for p in peerings:

        active = p['Status']['Code'] == 'active'

        findings.append(create_finding(
            "VPC-09",
            "VPC Peering Secure",
            "Low",
            "PASS" if active else "FAIL",
            p['VpcPeeringConnectionId'],
            "Peering active." if active else "Peering inactive.",
            "Review peering connection." if not active else "No action required.",
            {"status": p['Status']}
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