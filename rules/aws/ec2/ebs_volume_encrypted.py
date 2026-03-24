import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    volumes=ec2.describe_volumes()['Volumes']

    for v in volumes:

        vid=v['VolumeId']
        encrypted=v['Encrypted']

        findings.append(create_finding(
            "EBS-01","EBS Volume Encryption",
            "High" if not encrypted else "Low",
            "FAIL" if not encrypted else "PASS",
            vid,
            "Volume not encrypted." if not encrypted else "Volume encrypted.",
            "Enable encryption." if not encrypted else "No action required.",
            {"encrypted":encrypted}
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
        "category":"Storage",
        "resource_type":"aws_ebs_volume",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }