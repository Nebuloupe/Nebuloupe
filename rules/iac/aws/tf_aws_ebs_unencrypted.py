import uuid
import os
import re
import glob


def find_tf_files(search_dir="."):
    """Recursively find all .tf files under the given directory."""
    return glob.glob(os.path.join(search_dir, "**", "*.tf"), recursive=True)


def run_check(session, tf_path="."):
    """
    Static analysis rule: Detect EBS volumes in Terraform that do not have
    encryption enabled. Also checks EC2 launch templates and instances
    for unencrypted root/additional EBS block devices.
    """
    findings = []
    tf_files = find_tf_files(tf_path)

    if not tf_files:
        findings.append(create_finding(
            "IAC-AWS-EBS-01", "Terraform EBS Encryption", "Info",
            "PASS", "N/A",
            "No Terraform files found to scan.",
            "No action required.",
            {"scanned_files": 0}
        ))
        return findings

    all_content = ""
    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as f:
                all_content += f"\n# FILE: {tf_file}\n" + f.read()
        except Exception:
            continue

    # 1. Check standalone aws_ebs_volume resources
    ebs_pattern = re.compile(
        r'resource\s+"aws_ebs_volume"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for vol_name, vol_body in ebs_pattern.findall(all_content):
        encrypted = re.search(r'encrypted\s*=\s*(true|false)', vol_body, re.IGNORECASE)

        if encrypted and encrypted.group(1).lower() == "true":
            findings.append(create_finding(
                "IAC-AWS-EBS-01", "Terraform EBS Volume Encryption", "Low",
                "PASS", f"aws_ebs_volume.{vol_name}",
                f"EBS volume '{vol_name}' has encryption enabled.",
                "No action required.",
                {"volume": vol_name, "encrypted": True}
            ))
        else:
            findings.append(create_finding(
                "IAC-AWS-EBS-01", "Terraform EBS Volume Encryption", "High",
                "FAIL", f"aws_ebs_volume.{vol_name}",
                f"EBS volume '{vol_name}' does not have encryption enabled. "
                "Unencrypted volumes expose data at rest if the underlying storage "
                "is compromised or the volume snapshot is shared.",
                "Set encrypted = true on the aws_ebs_volume resource. Optionally "
                "specify a KMS key with kms_key_id for customer-managed encryption.",
                {"volume": vol_name, "encrypted": False}
            ))

    # 2. Check EC2 instances for unencrypted root/EBS block devices
    ec2_pattern = re.compile(
        r'resource\s+"aws_instance"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for instance_name, instance_body in ec2_pattern.findall(all_content):
        # Check root_block_device
        root_block = re.search(
            r'root_block_device\s*\{(.*?)\}', instance_body, re.DOTALL
        )
        if root_block:
            encrypted = re.search(r'encrypted\s*=\s*(true|false)', root_block.group(1), re.IGNORECASE)
            if not encrypted or encrypted.group(1).lower() != "true":
                findings.append(create_finding(
                    "IAC-AWS-EBS-01", "Terraform EC2 Root Volume Encryption", "High",
                    "FAIL", f"aws_instance.{instance_name}",
                    f"EC2 instance '{instance_name}' has an unencrypted root block device. "
                    "The root volume contains the OS and potentially sensitive configuration data.",
                    "Add encrypted = true to the root_block_device block.",
                    {"instance": instance_name, "block_type": "root_block_device", "encrypted": False}
                ))

        # Check ebs_block_device
        ebs_blocks = re.findall(
            r'ebs_block_device\s*\{(.*?)\}', instance_body, re.DOTALL
        )
        for i, ebs_block in enumerate(ebs_blocks):
            encrypted = re.search(r'encrypted\s*=\s*(true|false)', ebs_block, re.IGNORECASE)
            device_name = re.search(r'device_name\s*=\s*"([^"]+)"', ebs_block)
            dev_label = device_name.group(1) if device_name else f"device_{i}"

            if not encrypted or encrypted.group(1).lower() != "true":
                findings.append(create_finding(
                    "IAC-AWS-EBS-01", "Terraform EC2 EBS Block Encryption", "High",
                    "FAIL", f"aws_instance.{instance_name}",
                    f"EC2 instance '{instance_name}' has an unencrypted EBS block device "
                    f"({dev_label}). Data on this volume is not encrypted at rest.",
                    "Add encrypted = true to the ebs_block_device block.",
                    {"instance": instance_name, "device": dev_label, "encrypted": False}
                ))

    # 3. Check launch templates for unencrypted block device mappings
    lt_pattern = re.compile(
        r'resource\s+"aws_launch_template"\s+"(\w+)"\s*\{(.*?)\n\}',
        re.DOTALL
    )

    for lt_name, lt_body in lt_pattern.findall(all_content):
        block_devices = re.findall(
            r'block_device_mappings\s*\{(.*?)\}', lt_body, re.DOTALL
        )
        for bd in block_devices:
            ebs_block = re.search(r'ebs\s*\{(.*?)\}', bd, re.DOTALL)
            if ebs_block:
                encrypted = re.search(r'encrypted\s*=\s*"?(true|false)"?', ebs_block.group(1), re.IGNORECASE)
                if not encrypted or encrypted.group(1).lower() != "true":
                    findings.append(create_finding(
                        "IAC-AWS-EBS-01", "Terraform Launch Template EBS Encryption", "High",
                        "FAIL", f"aws_launch_template.{lt_name}",
                        f"Launch template '{lt_name}' defines an unencrypted EBS volume "
                        "in its block device mappings.",
                        "Set encrypted = true in the ebs block within block_device_mappings.",
                        {"launch_template": lt_name, "encrypted": False}
                    ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    """Helper to maintain Nebuloupe finding schema"""
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "aws",
        "category": "IaC Encryption",
        "resource_type": "aws_ebs_volume",
        "resource_id": res_id,
        "region": "N/A",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_volume",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
