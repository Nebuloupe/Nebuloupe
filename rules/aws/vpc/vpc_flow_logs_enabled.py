import uuid

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    vpcs = ec2.describe_vpcs()['Vpcs']
    logs = ec2.describe_flow_logs()['FlowLogs']

    enabled_vpcs = {l['ResourceId'] for l in logs}

    for v in vpcs:
        vid = v['VpcId']
        enabled = vid in enabled_vpcs

        findings.append(create_finding(
            "VPC-05",
            "VPC Flow Logs Enabled",
            "Medium" if not enabled else "Low",
            "FAIL" if not enabled else "PASS",
            vid,
            "Flow logs disabled." if not enabled else "Flow logs enabled.",
            "Enable VPC flow logs." if not enabled else "No action required.",
            {"flow_logs": enabled}
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
        "category": "Networking",
        "resource_type": "aws_security_group",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [],
        "resource_attributes": {},
        "evidence": evidence
    }
