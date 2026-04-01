import uuid

def run_check(session):
    ssm=session.client('ssm')
    findings=[]

    resp=ssm.describe_instance_information()

    managed={i['InstanceId'] for i in resp['InstanceInformationList']}

    for iid in managed:

        findings.append(create_finding(
            "EC2-06","SSM Agent Installed",
            "Low",
            "PASS",
            iid,
            "SSM agent installed.",
            "No action required.",
            {"managed_instance":iid}
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
        "category":"Management",
        "resource_type":"aws_ec2_instance",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }