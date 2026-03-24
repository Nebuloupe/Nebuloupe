import uuid

def run_check(session):
    ec2 = session.client("ec2")
    findings = []

    reservations = ec2.describe_instances()["Reservations"]

    for r in reservations:
        for inst in r["Instances"]:
            instance_id = inst["InstanceId"]

            monitoring = inst["Monitoring"]["State"] == "enabled"

            findings.append(create_finding(
                "EC2-03",
                "EC2 Detailed Monitoring",
                "Low" if monitoring else "Medium",
                "PASS" if monitoring else "FAIL",
                instance_id,
                "Detailed monitoring enabled." if monitoring else "Detailed monitoring disabled.",
                "Enable detailed monitoring for better metrics." if not monitoring else "No action required.",
                {"monitoring_state": inst["Monitoring"]}
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