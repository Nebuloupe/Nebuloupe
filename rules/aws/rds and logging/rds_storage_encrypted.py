import uuid

def run_check(session):
    rds = session.client('rds')
    findings = []

    dbs = rds.describe_db_instances()['DBInstances']

    for db in dbs:
        encrypted = db['StorageEncrypted']

        findings.append(create_finding(
            "RDS-02",
            "RDS Storage Encrypted",
            "High" if not encrypted else "Low",
            "FAIL" if not encrypted else "PASS",
            db['DBInstanceIdentifier'],
            "Storage not encrypted." if not encrypted else "Storage encrypted.",
            "Enable storage encryption." if not encrypted else "No action required.",
            {"encrypted": encrypted}
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