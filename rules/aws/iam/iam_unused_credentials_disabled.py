from datetime import datetime, timezone
import uuid 
def run_check(session):
    iam = session.client('iam')
    findings = []
    now = datetime.now(timezone.utc)
    try:
        users = iam.list_users()['Users']
        for user in users:
            keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
            for key in keys:
                key_id = key['AccessKeyId']
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)['AccessKeyLastUsed'].get('LastUsedDate')
                
                if last_used:
                    days_unused = (now - last_used).days
                    is_unused = days_unused > 90
                else:
                    is_unused = True # Never used
                
                if key['Status'] == 'Active' and is_unused:
                    findings.append(create_finding(
                        rule_id="IAM-06",
                        check="Unused Credentials Disabled",
                        severity="Low",
                        status="FAIL",
                        res_id=key_id,
                        desc=f"Access key {key_id} has not been used in 90+ days.",
                        rem="Deactivate or delete unused IAM access keys.",
                        evidence={"days_unused": days_unused if last_used else "Never"}
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