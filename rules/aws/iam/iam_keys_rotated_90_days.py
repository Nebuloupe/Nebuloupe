import uuid
from datetime import datetime, timezone

def run_check(session):
    iam = session.client('iam')
    findings = []
    MAX_AGE_DAYS = 90
    now = datetime.now(timezone.utc)

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                
                # List access keys for the user
                keys = iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                
                for key in keys:
                    if key['Status'] == 'Active':
                        create_date = key['CreateDate']
                        age_days = (now - create_date).days
                        key_id = key['AccessKeyId']
                        
                        is_old = age_days > MAX_AGE_DAYS
                        status = "FAIL" if is_old else "PASS"
                        
                        findings.append(create_finding(
                            rule_id="IAM-05",
                            check="Access Key Rotation",
                            severity="Medium" if is_old else "Low",
                            status=status,
                            res_id=f"arn:aws:iam::{key['UserName']}:key/{key_id}",
                            desc=f"Access Key {key_id} is {age_days} days old." if is_old else f"Access Key {key_id} is within rotation limits.",
                            rem="Rotate access keys every 90 days to reduce the impact of compromised credentials.",
                            evidence={"key_age_days": age_days, "key_id": key_id}
                        ))

    except Exception as e:
        findings.append(create_finding("IAM-05", "Access Key Rotation", "Medium", "FAIL", "aws_iam", str(e), "Check permissions.", {}))

    return findings

# Reuse the same create_finding helper as above...
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