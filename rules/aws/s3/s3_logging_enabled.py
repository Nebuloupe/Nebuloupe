import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        logging = s3.get_bucket_logging(Bucket=name)
        is_secure = 'LoggingEnabled' in logging

        findings.append(create_finding(
            "S3-09", "S3 Server Access Logging", "Low",
            "PASS" if is_secure else "FAIL", name,
            "Bucket logging is enabled." if is_secure else "Bucket logging is disabled.",
            "Configure server access logging for audit trails.",
            {"logging_config": logging.get('LoggingEnabled', 'None')}
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