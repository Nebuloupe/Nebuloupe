import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Virtual Machines are using managed disks (instead of unmanaged VHDs).
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            compute_client = ComputeManagementClient(credential, sub_id)

            for vm in compute_client.virtual_machines.list_all():
                try:
                    storage_profile = getattr(vm, 'storage_profile', None)
                    uses_managed_disks = False
                    
                    if storage_profile and getattr(storage_profile, 'os_disk', None):
                        if getattr(storage_profile.os_disk, 'managed_disk', None) is not None:
                            uses_managed_disks = True
                            
                    if not uses_managed_disks:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-7.6",
                            "check": "VM Not Using Managed Disks",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Compute",
                            "resource_type": "Microsoft.Compute/virtualMachines",
                            "resource_id": vm.id,
                            "region": vm.location,
                            "description": f"Virtual Machine '{vm.name}' is using unmanaged disks (vhd in storage account).",
                            "remediation": "Migrate the Virtual Machine to use Azure Managed Disks for better reliability and security.",
                            "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/windows/convert-unmanaged-to-managed-disks"],
                            "resource_attributes": {
                                "vm_name": vm.name,
                                "uses_managed_disks": False
                            },
                            "evidence": {
                                "uses_managed_disks": False
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze storage profile for VM {vm.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Managed Disks check: {e}")

    return findings