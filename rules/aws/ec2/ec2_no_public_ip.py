import uuid

def run_check(session):
    ec2 = session.client("ec2")
    findings = []

    reservations = ec2.describe_instances()["Reservations"]

    for r in reservations:
        for inst in r["Instances"]:
            instance_id = inst["InstanceId"]
            public_ip = inst.get("PublicIpAddress")

            has_public_ip = public_ip is not None

            findings.append(create_finding(
                "EC2-02",
                "EC2 Public IP Check",
                "Medium" if has_public_ip else "Low",
                "FAIL" if has_public_ip else "PASS",
                instance_id,
                "Instance has public IP." if has_public_ip else "Instance has no public IP.",
                "Remove public IP if not required." if has_public_ip else "No action required.",
                {"public_ip": public_ip}
            ))

    return findings
def create_finding(rule_id,check,severity,status,res_id,desc,rem,evidence):
    return{
        "finding_id":str(uuid.uuid4()),
        "rule_id":rule_id,
        "check":check,
        "severity":severity,
        "status":status,
        "cloud_provider":"aws",
        "category":"Networking",
        "resource_type":"aws_ec2_instance",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }