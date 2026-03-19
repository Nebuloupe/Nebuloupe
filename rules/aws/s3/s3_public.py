import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        try:
            status = s3.get_public_access_block(Bucket=name)
            config = status['PublicAccessBlockConfiguration']
            # If any block is False, it's a finding
            is_secure = all(config.values())
            
            findings.append(create_finding(
                "S3-01", "S3 Public Access Block", "High" if not is_secure else "Low",
                "PASS" if is_secure else "FAIL", name,
                "S3 bucket should have all public access blocked." if not is_secure else "S3 bucket has all public access blocked.",
                "Configure public access block settings to block all public access." if not is_secure else "No action required.",
                {"public_access_block": config}
            ))
        except Exception:
            findings.append(create_finding(
                "S3-01", "S3 Public Access Block", "High",
                "FAIL", name,
                "S3 bucket does not have public access block configured.",
                "Configure public access block settings to block all public access.",
                {"error": "Public access block not configured"}
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