import uuid

def run_check(session):
    ec2=session.client('ec2')
    findings=[]

    snapshots=ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']

    for s in snapshots:

        sid=s['SnapshotId']

        attr=ec2.describe_snapshot_attribute(
            SnapshotId=sid,
            Attribute='createVolumePermission'
        )

        public=len(attr['CreateVolumePermissions'])>0

        findings.append(create_finding(
            "EBS-02","EBS Snapshot Public",
            "High" if public else "Low",
            "FAIL" if public else "PASS",
            sid,
            "Snapshot is public." if public else "Snapshot private.",
            "Remove public permissions." if public else "No action required.",
            {"permissions":attr['CreateVolumePermissions']}
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
        "resource_type":"aws_ebs_snapshot",
        "resource_id":res_id,
        "region":"global",
        "description":desc,
        "remediation":rem,
        "references":[],
        "resource_attributes":{},
        "evidence":evidence
    }