import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    routes = ec2.describe_route_tables()['RouteTables']

    for rt in routes:
        open_route = False

        for r in rt['Routes']:
            if r.get('DestinationCidrBlock') == '0.0.0.0/0':
                open_route = True

        findings.append(create_finding(
            "VPC-07",
            "Route Table Least Privilege",
            "Medium" if open_route else "Low",
            "FAIL" if open_route else "PASS",
            rt['RouteTableId'],
            "Route allows internet traffic." if open_route else "Route restricted.",
            "Restrict route table." if open_route else "No action required.",
            {"routes": rt['Routes']}
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