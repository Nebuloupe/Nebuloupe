import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        if sg['GroupName'] == 'default':

            open_all = len(sg['IpPermissions']) > 0

            findings.append(create_finding(
                "VPC-04",
                "Default Security Group Open",
                "Medium" if open_all else "Low",
                "FAIL" if open_all else "PASS",
                sg['GroupId'],
                "Default SG allows traffic." if open_all else "Default SG locked down.",
                "Remove rules from default SG." if open_all else "No action required.",
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