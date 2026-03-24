import uuid

def run_check(session):
    ct = session.client('cloudtrail')
    findings = []

    trails = ct.describe_trails()['trailList']

    for t in trails:

        kms = t.get('KmsKeyId')

        findings.append(create_finding(
            "CT-03",
            "CloudTrail KMS Encryption",
            "High" if not kms else "Low",
            "FAIL" if not kms else "PASS",
            t['Name'],
            "CloudTrail not encrypted." if not kms else "CloudTrail encrypted.",
            "Enable KMS encryption." if not kms else "No action required.",
            {"kms_key": kms}
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
        "category": "Logging",
        "resource_type": "aws_cloudtrail",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [],
        "resource_attributes": {},
        "evidence": evidence
    }