import uuid

def run_check(session):
    ec2 = session.client("ec2")
    findings = []

    instances = ec2.describe_instances()["Reservations"]

    for r in instances:
        for inst in r["Instances"]:
            instance_id = inst["InstanceId"]
            metadata = inst.get("MetadataOptions", {})

            imds_v2 = metadata.get("HttpTokens") == "required"

            findings.append(create_finding(
                "EC2-01",
                "EC2 IMDSv2 Enforced",
                "High" if not imds_v2 else "Low",
                "PASS" if imds_v2 else "FAIL",
                instance_id,
                "IMDSv2 is required." if imds_v2 else "Instance allows IMDSv1.",
                "Set HttpTokens to required to enforce IMDSv2." if not imds_v2 else "No action required.",
                {"metadata_options": metadata}
            ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "Compute",
        "resource_type": "aws_ec2_instance",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        "resource_attributes": {},
        "evidence": evidence
    }