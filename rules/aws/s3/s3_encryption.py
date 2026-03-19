from botocore.exceptions import ClientError
import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
            findings.append(create_finding(
                "S3-02", "S3 Server-Side Encryption", "Low",
                "PASS", name,
                "S3 bucket has server-side encryption enabled.",
                "No action required.",
                {"encryption": encryption['ServerSideEncryptionConfiguration']}
            ))
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append(create_finding(
                    "S3-02", "S3 Server-Side Encryption", "Medium",
                    "FAIL", name,
                    "S3 bucket does not have server-side encryption configured.",
                    "Enable default server-side encryption for the bucket.",
                    {"error": "No encryption configuration"}
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
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"],
        "resource_attributes": {},
        "evidence": evidence
    }