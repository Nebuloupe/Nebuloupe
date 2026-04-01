import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    eips=ec2.describe_addresses()['Addresses']

    for e in eips:

        alloc=e.get('AllocationId',"unknown")
        unused='InstanceId' not in e

        findings.append(create_finding(
            "EC2-05","Unused Elastic IP",
            "Low" if not unused else "Medium",
            "FAIL" if unused else "PASS",
            alloc,
            "Elastic IP unused." if unused else "Elastic IP in use.",
            "Release unused Elastic IP." if unused else "No action required.",
            {"eip":e}
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
        "resource_type":"aws_eip",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }