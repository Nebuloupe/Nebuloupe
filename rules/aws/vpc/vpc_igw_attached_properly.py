import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    igws = ec2.describe_internet_gateways()['InternetGateways']

    for igw in igws:

        attached = len(igw['Attachments']) > 0

        findings.append(create_finding(
            "VPC-10",
            "Internet Gateway Attached",
            "Medium" if not attached else "Low",
            "FAIL" if not attached else "PASS",
            igw['InternetGatewayId'],
            "IGW not attached to VPC." if not attached else "IGW attached properly.",
            "Attach IGW to VPC." if not attached else "No action required.",
            {"attachments": igw['Attachments']}
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