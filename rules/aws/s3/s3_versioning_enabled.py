import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        versioning = s3.get_bucket_versioning(Bucket=name).get('Status', 'Disabled')
        is_secure = versioning == 'Enabled'

        findings.append(create_finding(
            "S3-08", "S3 Versioning Enabled", "Medium" if not is_secure else "Low",
            "PASS" if is_secure else "FAIL", name,
            "Versioning is enabled." if is_secure else "Versioning is not enabled.",
            "Enable versioning to protect against accidental overwrites/deletions.",
            {"versioning_status": versioning}
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