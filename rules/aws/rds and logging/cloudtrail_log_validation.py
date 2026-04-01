import uuid

def run_check(session):
    ct = session.client('cloudtrail')
    findings = []

    trails = ct.describe_trails()['trailList']

    for t in trails:

        status = ct.get_trail_status(Name=t['Name'])
        validation = status.get('LogFileValidationEnabled', False)

        findings.append(create_finding(
            "CT-02",
            "CloudTrail Log Validation",
            "Medium" if not validation else "Low",
            "FAIL" if not validation else "PASS",
            t['Name'],
            "Log validation disabled." if not validation else "Log validation enabled.",
            "Enable log file validation." if not validation else "No action required.",
            {"validation": validation}
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