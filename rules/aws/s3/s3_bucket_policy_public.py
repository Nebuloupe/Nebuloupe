import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=name)
            is_public = policy_status['PolicyStatus'].get('IsPublic', False)
        except:
            is_public = False # No policy usually means not public via policy

        findings.append(create_finding(
            "S3-04", "S3 Public Policy Check", "High" if is_public else "Low",
            "FAIL" if is_public else "PASS", name,
            "Bucket policy allows public access." if is_public else "Bucket policy is private.",
            "Restrict the bucket policy to specific IAM principals.",
            {"is_public_policy": is_public}
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