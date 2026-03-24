import uuid

def run_check(session):
    ct = session.client('cloudtrail')
    findings = []

    trails = ct.describe_trails()['trailList']

    for t in trails:

        multi = t.get('IsMultiRegionTrail', False)

        findings.append(create_finding(
            "CT-01",
            "CloudTrail Multi Region Enabled",
            "High" if not multi else "Low",
            "FAIL" if not multi else "PASS",
            t['Name'],
            "CloudTrail not multi-region." if not multi else "CloudTrail multi-region enabled.",
            "Enable multi-region logging." if not multi else "No action required.",
            {"multi_region": multi}
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