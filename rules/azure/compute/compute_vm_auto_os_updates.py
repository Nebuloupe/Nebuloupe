import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Virtual Machines have automatic OS updates enabled.
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
                    auto_update = False
                    os_type = "Unknown"
                    
                    if os_profile:
                        # Windows VM check
                        if getattr(os_profile, 'windows_configuration', None):
                            os_type = "Windows"
                            auto_update = getattr(os_profile.windows_configuration, 'enable_automatic_updates', False)
                            
                        # Linux VM check
                        elif getattr(os_profile, 'linux_configuration', None):
                            os_type = "Linux"
                            patch_settings = getattr(os_profile.linux_configuration, 'patch_settings', None)
                            if patch_settings:
                                mode = getattr(patch_settings, 'patch_mode', '').lower()
                                if mode in ['automaticbyplatform', 'automaticbyos']:
                                    auto_update = True
                                    
                    if not auto_update and os_profile:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-7.4",
                            "check": "VM OS Automatic Updates Disabled",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Compute",
                            "resource_type": "Microsoft.Compute/virtualMachines",
                            "resource_id": vm.id,
                            "region": vm.location,
                            "description": f"{os_type} Virtual Machine '{vm.name}' does not have automatic OS updates enabled.",
                            "remediation": "Enable automatic updates configuration on the Virtual Machine OS profile.",
                            "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/automatic-vm-guest-patching"],
                            "resource_attributes": {
                                "vm_name": vm.name,
                                "os_type": os_type,
                                "auto_update_enabled": False
                            },
                            "evidence": {
                                "os_profile_configured": True,
                                "auto_update_enabled": False
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze OS updates for VM {vm.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Auto Updates check: {e}")

    return findings