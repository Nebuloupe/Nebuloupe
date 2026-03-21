from botocore.exceptions import ClientError

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        try:
            s3.get_bucket_encryption(Bucket=name)
            findings.append({"resource": name, "status": "PASS", "finding": "Encryption Enabled"})
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({"resource": name, "status": "FAIL", "finding": "Unencrypted Bucket"})
    return findings