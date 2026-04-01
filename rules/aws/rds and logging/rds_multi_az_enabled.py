import uuid

def run_check(session):
    rds = session.client('rds')
    findings = []

    dbs = rds.describe_db_instances()['DBInstances']

    for db in dbs:

        multi = db['MultiAZ']

        findings.append(create_finding(
            "RDS-05",
            "RDS Multi AZ Enabled",
            "Medium" if not multi else "Low",
            "FAIL" if not multi else "PASS",
            db['DBInstanceIdentifier'],
            "Multi AZ disabled." if not multi else "Multi AZ enabled.",
            "Enable Multi AZ." if not multi else "No action required.",
            {"multi_az": multi}
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