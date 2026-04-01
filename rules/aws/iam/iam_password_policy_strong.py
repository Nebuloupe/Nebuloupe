import uuid
def run_check(session):
    iam = session.client('iam')
    findings = []
    try:
        policy = iam.get_account_password_policy().get('PasswordPolicy', {})
        # Check for standard 'strong' criteria
        is_strong = all([
            policy.get('MinimumPasswordLength', 0) >= 14,
            policy.get('RequireUppercaseCharacters', False),
            policy.get('RequireLowercaseCharacters', False),
            policy.get('RequireNumbers', False),
            policy.get('RequireSymbols', False)
        ])
        
        findings.append(create_finding(
            rule_id="IAM-05",
            check="Strong Password Policy",
            severity="Medium",
            status="PASS" if is_strong else "FAIL",
            res_id="account-password-policy",
            desc="Password policy meets complexity requirements." if is_strong else "Password policy is too weak.",
            rem="Update IAM password policy to require 14+ chars, symbols, and mixed case.",
            evidence=policy
        ))
    except iam.exceptions.NoSuchEntityException:
        # No policy exists at all
        findings.append(create_finding(rule_id="IAM-05", check="Strong Password Policy", severity="High", status="FAIL", res_id="account-password-policy", desc="No password policy defined.", rem="Create a strong IAM password policy.", evidence={}))
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