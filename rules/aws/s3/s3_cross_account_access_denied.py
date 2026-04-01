import uuid, json

def run_check(session):
    s3 = session.client('s3')
    sts = session.client('sts')
    account_id = sts.get_caller_identity()['Account']
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        cross_account = False
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
            policy_str = json.dumps(policy)
            # Simple check: if another account ID (12 digits) is found that isn't ours
            # This is a simplified logic for the sample
            if any(char.isdigit() for char in policy_str) and account_id not in policy_str:
                cross_account = True
        except: pass

        findings.append(create_finding(
            "S3-07", "S3 Cross Account Access", "High" if cross_account else "Low",
            "FAIL" if cross_account else "PASS", name,
            "Bucket policy may allow external AWS account access." if cross_account else "No cross-account access detected.",
            "Verify and remove any unauthorized external AWS Principals.",
            {}
        ))
    return findings
def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    """Helper to maintain Nebuloupe finding schema"""
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "Storage",
        "resource_type": "aws_s3_bucket",
        "resource_id": res_id,
        "region": "global",  # S3 is global, but could be bucket region
        "description": desc,
        "remediation": rem,
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        "resource_attributes": {},
        "evidence": evidence
    }