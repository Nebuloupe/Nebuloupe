import uuid

def run_check(session):
    iam = session.client('iam')
    findings = []
    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            # Check inline policies
            inline = iam.list_user_policies(UserName=username)['PolicyNames']
            # Check attached managed policies
            attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
            
            has_policies = len(inline) > 0 or len(attached) > 0
            status = "FAIL" if has_policies else "PASS"
            
            findings.append(create_finding(
                rule_id="IAM-03",
                check="No Direct Policies on Users",
                severity="Medium",
                status=status,
                res_id=username,
                desc=f"User {username} has direct policies attached." if has_policies else f"User {username} has no direct policies.",
                rem="Move user policies to an IAM Group and add the user to that group.",
                evidence={"inline_policies": inline, "attached_policies": attached}
            ))
    except Exception as e:
        # Standard error handling as per your template
        pass 
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