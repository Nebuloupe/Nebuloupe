import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Linux Virtual Machines have password authentication disabled (favoring SSH Keys).
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
                    os_profile = getattr(vm, 'os_profile', None)
                    
                    if os_profile and getattr(os_profile, 'linux_configuration', None):
                        linux_config = os_profile.linux_configuration
                        pwd_disabled = getattr(linux_config, 'disable_password_authentication', False)
                                    
                        if not pwd_disabled:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-7.1", 
                                "check": "Linux VM Password Authentication Enabled",
                                "severity": "Medium",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Compute",
                                "resource_type": "Microsoft.Compute/virtualMachines",
                                "resource_id": vm.id,
                                "region": vm.location,
                                "description": f"Linux Virtual Machine '{vm.name}' has password authentication enabled.",
                                "remediation": "Disable password authentication on the VM and use SSH keys instead.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys"],
                                "resource_attributes": {
                                    "vm_name": vm.name,
                                    "disable_password_authentication": False
                                },
                                "evidence": {
                                    "disable_password_authentication": False
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-7.1", 
                                "check": "Linux VM Password Authentication Enabled",
                                "severity": "Medium",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "Compute",
                                "resource_type": "Microsoft.Compute/virtualMachines",
                                "resource_id": vm.id,
                                "region": vm.location,
                                "description": f"Linux Virtual Machine '{vm.name}' has password authentication disabled.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/linux/mac-create-ssh-keys"],
                                "resource_attributes": {
                                    "vm_name": vm.name,
                                    "disable_password_authentication": True
                                },
                                "evidence": {
                                    "disable_password_authentication": True
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze linux config for VM {vm.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Guest Auth check: {e}")

    return findings