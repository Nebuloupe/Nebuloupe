import uuid

def run_check(session):
    config = session.client('config')
    findings = []

    recorders = config.describe_configuration_recorders()['ConfigurationRecorders']

    enabled = len(recorders) > 0

    findings.append(create_finding(
        "CFG-01",
        "AWS Config Enabled",
        "High" if not enabled else "Low",
        "FAIL" if not enabled else "PASS",
        "account",
        "AWS Config not enabled." if not enabled else "AWS Config enabled.",
        "Enable AWS Config." if not enabled else "No action required.",
        {"recorders": len(recorders)}
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