import uuid
def run_check(session):
    # Access Analyzer is regional
    aa = session.client('accessanalyzer')
    findings = []
    try:
        analyzers = aa.list_analyzers()['analyzers']
        # Active analyzers in the account
        active = [a for a in analyzers if a['status'] == 'ACTIVE']
        
        status = "PASS" if active else "FAIL"
        findings.append(create_finding(
            rule_id="IAM-08",
            check="Access Analyzer Enabled",
            severity="Low",
            status=status,
            res_id="iam-access-analyzer",
            desc="IAM Access Analyzer is enabled." if active else "IAM Access Analyzer is not enabled.",
            rem="Enable IAM Access Analyzer to monitor for external resource sharing.",
            evidence={"active_analyzers_count": len(active)}
        ))
    except Exception as e: pass
    return findings
def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    """Helper to maintain your Nebuloupe finding schema"""
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "IAM",
        "resource_type": "aws_iam",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_root.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }