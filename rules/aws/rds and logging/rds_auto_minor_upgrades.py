import uuid

def run_check(session):
    rds = session.client('rds')
    findings = []

    dbs = rds.describe_db_instances()['DBInstances']

    for db in dbs:
        auto = db['AutoMinorVersionUpgrade']

        findings.append(create_finding(
            "RDS-03",
            "RDS Auto Minor Version Upgrade",
            "Medium" if not auto else "Low",
            "FAIL" if not auto else "PASS",
            db['DBInstanceIdentifier'],
            "Auto upgrades disabled." if not auto else "Auto upgrades enabled.",
            "Enable auto minor upgrades." if not auto else "No action required.",
            {"auto_upgrade": auto}
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