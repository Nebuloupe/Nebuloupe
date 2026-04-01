import uuid

DB_PORTS = [3306, 5432, 1433, 1521]

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        db_open = False

        for rule in sg['IpPermissions']:
            port = rule.get('FromPort')
            if port in DB_PORTS:
                for ip in rule.get('IpRanges', []):
                    if ip['CidrIp'] == '0.0.0.0/0':
                        db_open = True

        findings.append(create_finding(
            "VPC-03",
            "Database Ports Open",
            "Critical" if db_open else "Low",
            "FAIL" if db_open else "PASS",
            sg['GroupId'],
            "Database port open to internet." if db_open else "Database ports secure.",
            "Restrict DB port access." if db_open else "No action required.",
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