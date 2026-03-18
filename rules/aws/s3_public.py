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
            
            findings.append({
                "resource": name,
                "status": "PASS" if is_secure else "FAIL",
                "finding": "All Public Access Blocked" if is_secure else "Public Access Allowed"
            })
        except Exception:
            findings.append({"resource": name, "status": "FAIL", "finding": "Public Access Block Not Configured"})
            
    return findings