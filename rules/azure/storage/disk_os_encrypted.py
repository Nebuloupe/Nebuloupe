import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Azure Virtual Machine OS Disks are encrypted.
    """
    findings = []

    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            compute_client = ComputeManagementClient(credential, sub_id)

            # Iterate through all disks
            for disk in compute_client.disks.list():
                try:
                    # Check if it's an OS disk
                    if getattr(disk, "os_type", None) is not None:
                        is_encrypted = False
                        
                        # Check disk encryption
                        encryption = getattr(disk, "encryption", None)
                        if encryption:
                            # Usually values are 'EncryptionAtRestWithPlatformKey', 'EncryptionAtRestWithCustomerKey', etc.
                            # 'None' means not encrypted.
                            enc_type = getattr(encryption, "type", "None")
                            if enc_type and enc_type.lower() != "none" and enc_type != "":
                                is_encrypted = True
                                
                        if not is_encrypted:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-7.1",
                                "check": "OS Disk is not Encrypted",
                                "severity": "High",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Compute/disks",
                                "resource_id": disk.id,
                                "region": disk.location,
                                "description": f"OS Disk '{disk.name}' does not have encryption enabled.",
                                "remediation": "Enable Azure Disk Encryption (ADE) on the virtual machine.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview"],
                                "resource_attributes": {
                                    "os_type": disk.os_type.name if hasattr(disk.os_type, 'name') else str(disk.os_type),
                                    "encryption_type": str(getattr(encryption, "type", "None")) if encryption else "None"
                                },
                                "evidence": {
                                    "encryption": str(getattr(encryption, "type", "None")) if encryption else "None"
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-7.1",
                                "check": "OS Disk is not Encrypted",
                                "severity": "High",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Compute/disks",
                                "resource_id": disk.id,
                                "region": disk.location,
                                "description": f"OS Disk '{disk.name}' has encryption enabled.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview"],
                                "resource_attributes": {
                                    "os_type": disk.os_type.name if hasattr(disk.os_type, 'name') else str(disk.os_type),
                                    "encryption_type": str(getattr(encryption, "type", "None")) if encryption else "None"
                                },
                                "evidence": {
                                    "encryption": str(getattr(encryption, "type", "None")) if encryption else "None"
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze encryption for OS disk {disk.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for OS disk encryption check: {e}")

    return findings