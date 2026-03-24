import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    vpcs=ec2.describe_vpcs()['Vpcs']

    default_vpcs={v['VpcId'] for v in vpcs if v.get('IsDefault')}

    reservations=ec2.describe_instances()['Reservations']

    for r in reservations:
        for inst in r['Instances']:

            iid=inst['InstanceId']
            vpc=inst.get('VpcId')

            in_default=vpc in default_vpcs

            findings.append(create_finding(
                "EC2-07","Instance in Default VPC",
                "Medium" if in_default else "Low",
                "FAIL" if in_default else "PASS",
                iid,
                "Instance running in default VPC." if in_default else "Instance not in default VPC.",
                "Move instance to custom VPC." if in_default else "No action required.",
                {"vpc":vpc}
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