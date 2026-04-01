import uuid

def run_check(session):
    s3 = session.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])
    findings = []

    for b in buckets:
        name = b['Name']
        acl = s3.get_bucket_acl(Bucket=name)
        is_public = any(g.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' 
                        and g.get('Permission') in ['WRITE', 'FULL_CONTROL'] for g in acl['Grants'])
        
        findings.append(create_finding(
            "S3-03", "S3 Public Write Access", "Critical" if is_public else "Low",
            "FAIL" if is_public else "PASS", name,
            "Bucket allows public write access via ACL." if is_public else "Bucket does not allow public write.",
            "Remove public WRITE permissions from bucket ACL immediately.",
            {"acl_grants": acl['Grants']}
        ))
    return findings

# [Include same create_finding helper here]
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