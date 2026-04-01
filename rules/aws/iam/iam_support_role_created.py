import uuid
def run_check(session):
    iam = session.client('iam')
    findings = []
    found_role = False
    try:
        roles = iam.list_roles()['Roles']
        for role in roles:
            attached = iam.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']
            if any(p['PolicyArn'] == 'arn:aws:iam::aws:policy/AWSSupportAccess' for p in attached):
                found_role = True
                break
        
        findings.append(create_finding(
            rule_id="IAM-07",
            check="Support Role Created",
            severity="Low",
            status="PASS" if found_role else "FAIL",
            res_id="support-role",
            desc="A role for AWS Support access exists." if found_role else "No role found with AWSSupportAccess policy.",
            rem="Create an IAM role with the AWSSupportAccess managed policy.",
            evidence={"support_role_found": found_role}
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