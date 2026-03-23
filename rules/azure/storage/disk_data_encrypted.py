import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Azure Virtual Machine Data Disks are encrypted.
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
                    # Check if it's a Data disk (os_type is None)
                    if getattr(disk, "os_type", None) is None:
                        is_encrypted = False
                        
                        # Check disk encryption
                        encryption = getattr(disk, "encryption", None)
                        if encryption:
                            enc_type = getattr(encryption, "type", "None")
                            if enc_type and enc_type.lower() != "none" and enc_type != "":
                                is_encrypted = True
                                
                        if not is_encrypted:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-7.2",
                                "check": "Data Disk is not Encrypted",
                                "severity": "High",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Compute/disks",
                                "resource_id": disk.id,
                                "region": disk.location,
                                "description": f"Data Disk '{disk.name}' does not have encryption enabled.",
                                "remediation": "Enable Azure Disk Encryption (ADE) on the virtual machine attached to this data disk.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview"],
                                "resource_attributes": {
                                    "disk_type": "DataDisk",
                                    "encryption_type": str(getattr(encryption, "type", "None")) if encryption else "None"
                                },
                                "evidence": {
                                    "encryption": str(getattr(encryption, "type", "None")) if encryption else "None"
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze encryption for Data disk {disk.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Data disk encryption check: {e}")

    return findings