import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    resp=ec2.get_ebs_encryption_by_default()

    enabled=resp['EbsEncryptionByDefault']

    findings.append(create_finding(
        "EBS-03","EBS Default Encryption",
        "High" if not enabled else "Low",
        "FAIL" if not enabled else "PASS",
        "account",
        "Default EBS encryption disabled." if not enabled else "Default encryption enabled.",
        "Enable default EBS encryption." if not enabled else "No action required.",
        {"default_encryption":enabled}
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
        "resource_type":"aws_account",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }