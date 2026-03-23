import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        try:
            lock = s3.get_object_lock_configuration(Bucket=name)
            enabled = lock['ObjectLockConfiguration']['ObjectLockEnabled'] == 'Enabled'
        except:
            enabled = False

        findings.append(create_finding(
            "S3-06", "S3 Object Lock", "Low",
            "PASS" if enabled else "FAIL", name,
            "Object lock is enabled." if enabled else "Object lock is disabled.",
            "Enable Object Lock if data immutability is required.",
            {"object_lock_status": "Enabled" if enabled else "Disabled"}
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