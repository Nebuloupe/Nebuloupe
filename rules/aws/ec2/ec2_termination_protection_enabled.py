import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    reservations=ec2.describe_instances()['Reservations']

    for r in reservations:
        for inst in r['Instances']:

            iid=inst['InstanceId']

            attr=ec2.describe_instance_attribute(
                InstanceId=iid,
                Attribute='disableApiTermination'
            )

            enabled=attr['DisableApiTermination']['Value']

            findings.append(create_finding(
                "EC2-04","Termination Protection",
                "Medium" if not enabled else "Low",
                "FAIL" if not enabled else "PASS",
                iid,
                "Termination protection disabled." if not enabled else "Termination protection enabled.",
                "Enable termination protection." if not enabled else "No action required.",
                {"termination_protection":enabled}
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
        "category":"Compute",
        "resource_type":"aws_ec2_instance",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }