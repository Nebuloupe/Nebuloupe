import uuid

def run_check(session):
    iam = session.client('iam')
    findings = []

    try:
        # Get the account summary which contains root-specific security flags
        summary = iam.get_account_summary()
        # AccountMFAEnabled: 1 if root has MFA, 0 if not
        root_mfa_active = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0) == 1
        
        status = "PASS" if root_mfa_active else "FAIL"
        severity = "Critical" if not root_mfa_active else "Low"
        
        description = (
            "Multi-Factor Authentication (MFA) is enabled for the root account." if root_mfa_active 
            else "The root account does not have Multi-Factor Authentication (MFA) enabled."
        )
        
        remediation = (
            "No action required." if root_mfa_active 
            else "Enable a hardware or virtual MFA device for the root user immediately."
        )

        findings.append(create_finding(
            rule_id="IAM-02",
            check="Root MFA Enabled",
            severity=severity,
            status=status,
            res_id="root-account",
            desc=description,
            rem=remediation,
            evidence={"mfa_active": root_mfa_active}
        ))

    except Exception as e:
        findings.append(create_finding(
            rule_id="IAM-02",
            check="Root MFA Enabled",
            severity="Critical",
            status="FAIL",
            res_id="root-account",
            desc=f"Error checking root MFA status: {str(e)}",
            rem="Ensure the scanner has 'iam:GetAccountSummary' permissions.",
            evidence={"error": str(e)}
        ))

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