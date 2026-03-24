import uuid

def run_check(session):
    rds = session.client('rds')
    findings = []

    snaps = rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']

    for s in snaps:

        attr = rds.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=s['DBSnapshotIdentifier']
        )

        public = False

        for a in attr['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
            if a['AttributeName'] == 'restore' and 'all' in a['AttributeValues']:
                public = True

        findings.append(create_finding(
            "RDS-04",
            "RDS Snapshot Public",
            "High" if public else "Low",
            "FAIL" if public else "PASS",
            s['DBSnapshotIdentifier'],
            "Snapshot is public." if public else "Snapshot private.",
            "Remove public snapshot permissions." if public else "No action required.",
            {"snapshot_public": public}
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
        "resource_type": "aws_rds_snapshot",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [],
        "resource_attributes": {},
        "evidence": evidence
    }