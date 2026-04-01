import uuid
from botocore.exceptions import ClientError

def run_check(session):
    ec2 = session.client('ec2')
    findings = []

    try:
        resp = ec2.describe_vpc_classic_link()
        vpcs = resp['Vpcs']

        for v in vpcs:

            enabled = v.get('ClassicLinkEnabled', False)

            findings.append(create_finding(
                "VPC-06",
                "VPC ClassicLink Disabled",
                "Medium" if enabled else "Low",
                "FAIL" if enabled else "PASS",
                v['VpcId'],
                "ClassicLink enabled." if enabled else "ClassicLink disabled.",
                "Disable ClassicLink." if enabled else "No action required.",
                {"classic_link": enabled}
            ))

    except ClientError as e:

        # Handle regions where ClassicLink doesn't exist
        if "UnsupportedOperation" in str(e):

            findings.append(create_finding(
                "VPC-06",
                "VPC ClassicLink Disabled",
                "Low",
                "PASS",
                "region",
                "ClassicLink not supported in this region.",
                "No action required.",
                {"note": "ClassicLink deprecated by AWS"}
            ))

        else:
            raise e

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "Networking",
        "resource_type": "aws_vpc",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": ["https://docs.aws.amazon.com/vpc/latest/classiclink/what-is-classiclink.html"],
        "resource_attributes": {},
        "evidence": evidence
    }