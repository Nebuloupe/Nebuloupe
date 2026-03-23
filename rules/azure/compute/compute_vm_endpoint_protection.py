import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Virtual Machines have endpoint protection installed (e.g., Microsoft Antimalware, Defender).
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
                    rg_name = vm.id.split('/')[4]
                    extensions = compute_client.virtual_machine_extensions.list(rg_name, vm.name)
                    
                    has_endpoint_protection = False
                    installed_extensions = []
                    
                    for ext in extensions:
                        ext_type = getattr(ext, 'type_properties_type', '').lower()
                        publisher = getattr(ext, 'publisher', '').lower()
                        installed_extensions.append(f"{publisher}/{ext_type}")
                        
                        # Check for MS Antimalware or Defender extensions
                        if 'iaasantimalware' in ext_type or 'endpointprotection' in ext_type or 'defender' in ext_type or 'defender' in publisher:
                            has_endpoint_protection = True
                            
                    if not has_endpoint_protection:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-7.5", 
                            "check": "Endpoint Protection not installed on VM",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Compute",
                            "resource_type": "Microsoft.Compute/virtualMachines",
                            "resource_id": vm.id,
                            "region": vm.location,
                            "description": f"Virtual Machine '{vm.name}' does not have a recognized endpoint protection (antimalware) extension installed.",
                            "remediation": "Deploy the Microsoft Antimalware or Microsoft Defender for Endpoint extension to the VM.",
                            "references": ["https://learn.microsoft.com/en-us/azure/security/fundamentals/antimalware"],
                            "resource_attributes": {
                                "vm_name": vm.name,
                                "has_endpoint_protection": False
                            },
                            "evidence": {
                                "installed_extensions": installed_extensions
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze VM extensions for Antimalware {vm.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Endpoint Protection check: {e}")

    return findings