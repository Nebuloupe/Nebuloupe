import uuid
def run_check(session):
    iam = session.client('iam')
    findings = []
    try:
        policies = iam.list_policies(Scope='Local')['Policies']
        for policy in policies:
            arn = policy['Arn']
            version_id = policy['DefaultVersionId']
            policy_ver = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            statements = policy_ver['PolicyVersion']['Document']['Statement']
            
            if not isinstance(statements, list): statements = [statements]
            
            full_admin = any(s.get('Effect') == 'Allow' and s.get('Action') == '*' and s.get('Resource') == '*' for s in statements)
            
            findings.append(create_finding(
                rule_id="IAM-04",
                check="No Star-Star Policies",
                severity="High",
                status="FAIL" if full_admin else "PASS",
                res_id=arn,
                desc="Policy grants full '*' administrative access." if full_admin else "Policy does not grant full '*' access.",
                rem="Restrict the policy to specific actions and resources (Least Privilege).",
                evidence={"is_full_admin": full_admin}
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