import uuid

def run_check(session):
    rds = session.client('rds')
    findings = []

    dbs = rds.describe_db_instances()['DBInstances']

    for db in dbs:
        public = db['PubliclyAccessible']

        findings.append(create_finding(
            "RDS-01",
            "RDS Not Publicly Accessible",
            "High" if public else "Low",
            "FAIL" if public else "PASS",
            db['DBInstanceIdentifier'],
            "Database is publicly accessible." if public else "Database not publicly accessible.",
            "Disable public access." if public else "No action required.",
            {"public_access": public}
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
        "category": "Database",
        "resource_type": "aws_rds_instance",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [],
        "resource_attributes": {},
        "evidence": evidence
    }