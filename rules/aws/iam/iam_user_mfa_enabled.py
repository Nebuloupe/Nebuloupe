import uuid

def run_check(session):
    iam = session.client('iam')
    findings = []

    try:
        # 1. Get all users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                user_arn = user['Arn']
                
                # 2. Check if user has MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=username).get('MFADevices', [])
                has_mfa = len(mfa_devices) > 0
                
                # 3. Check if user has a login profile (console access)
                has_console = False
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                # We only FAIL if they have console access but no MFA
                status = "PASS"
                if has_console and not has_mfa:
                    status = "FAIL"
                
                severity = "High" if status == "FAIL" else "Low"

                findings.append(create_finding(
                    rule_id="IAM-04",
                    check="User MFA Enabled",
                    severity=severity,
                    status=status,
                    res_id=user_arn,
                    desc=f"User {username} has MFA enabled." if has_mfa else f"User {username} has console access but no MFA enabled.",
                    rem="Enforce MFA for all IAM users with console access.",
                    evidence={"mfa_active": has_mfa, "console_access": has_console}
                ))

    except Exception as e:
        findings.append(create_finding("IAM-04", "User MFA Enabled", "High", "FAIL", "aws_iam", str(e), "Check permissions.", {}))

    return findings

def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "IAM",
        "resource_type": "aws_iam_user",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_cli_api.html"],
        "resource_attributes": {},
        "evidence": evidence
    }