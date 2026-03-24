import uuid

def run_check(session):
    cw = session.client('cloudwatch')
    findings = []

    alarms = cw.describe_alarms()['MetricAlarms']

    configured = len(alarms) > 0

    findings.append(create_finding(
        "CW-01",
        "CloudWatch Alarms Configured",
        "Medium" if not configured else "Low",
        "FAIL" if not configured else "PASS",
        "account",
        "No alarms configured." if not configured else "CloudWatch alarms present.",
        "Create monitoring alarms." if not configured else "No action required.",
        {"alarm_count": len(alarms)}
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