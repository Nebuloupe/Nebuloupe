import uuid

def run_check(session):
    iam = session.client('iam')
    findings = []

    try:
        # The AccountSummary gives us a quick count of root access keys
        summary = iam.get_account_summary()
        root_keys_count = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
        
        # Determine status based on AWS Best Practices
        is_secure = (root_keys_count == 0)
        status = "PASS" if is_secure else "FAIL"
        severity = "Critical" if not is_secure else "Low"
        
        description = (
            "The root account has no active access keys." if is_secure 
            else f"The root account currently has {root_keys_count} active access key(s)."
        )
        
        remediation = (
            "No action required." if is_secure 
            else "Delete all root access keys immediately and use IAM roles or users for daily tasks."
        )

        findings.append(create_finding(
            rule_id="IAM-01",
            check="No Root Access Keys",
            severity=severity,
            status=status,
            res_id="root-account",
            desc=description,
            rem=remediation,
            evidence={"root_access_keys_present": root_keys_count}
        ))

    except Exception as e:
        # Fallback for API errors or permission issues
        findings.append(create_finding(
            rule_id="IAM-01",
            check="No Root Access Keys",
            severity="Critical",
            status="FAIL",
            res_id="root-account",
            desc=f"Error checking root access keys: {str(e)}",
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
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }