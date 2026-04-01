import uuid, json

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        secure_transport = False
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=name)['Policy'])
            for stmt in policy.get('Statement', []):
                if stmt.get('Effect') == 'Deny' and stmt.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false':
                    secure_transport = True
        except:
            pass

        findings.append(create_finding(
            "S3-05", "S3 Secure Transport", "Medium" if not secure_transport else "Low",
            "FAIL" if not secure_transport else "PASS", name,
            "Bucket does not enforce HTTPS via policy." if not secure_transport else "Bucket enforces HTTPS.",
            "Add a Deny statement for aws:SecureTransport: false in the bucket policy.",
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