import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.compute import ComputeManagementClient

def run_check(credential):
    """
    Checks if Virtual Machines have a vulnerability scanner extension installed (e.g., Qualys, Defender).
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
                    
                    has_vuln_scanner = False
                    installed_extensions = []
                    
                    for ext in extensions:
                        ext_type = getattr(ext, 'type_properties_type', '').lower()
                        publisher = getattr(ext, 'publisher', '').lower()
                        installed_extensions.append(f"{publisher}/{ext_type}")
                        
                        # Check for common vulnerability scanner extensions
                        if 'qualys' in publisher or 'vulnerabilityassessment' in ext_type or 'vulnerability' in ext_type:
                            has_vuln_scanner = True
                            
                    if not has_vuln_scanner:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-7.3", 
                            "check": "Vulnerability Scanner not installed on VM",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Compute",
                            "resource_type": "Microsoft.Compute/virtualMachines",
                            "resource_id": vm.id,
                            "region": vm.location,
                            "description": f"Virtual Machine '{vm.name}' does not have a recognized vulnerability assessment extension installed.",
                            "remediation": "Deploy a vulnerability scanner extension (such as integrated Defender for Cloud / Qualys) to the VM.",
                            "references": ["https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm"],
                            "resource_attributes": {
                                "vm_name": vm.name,
                                "has_vuln_scanner": False
                            },
                            "evidence": {
                                "installed_extensions": installed_extensions
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-7.3", 
                            "check": "Vulnerability Scanner not installed on VM",
                            "severity": "High",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Compute",
                            "resource_type": "Microsoft.Compute/virtualMachines",
                            "resource_id": vm.id,
                            "region": vm.location,
                            "description": f"Virtual Machine '{vm.name}' has a recognized vulnerability assessment extension installed.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm"],
                            "resource_attributes": {
                                "vm_name": vm.name,
                                "has_vuln_scanner": True
                            },
                            "evidence": {
                                "installed_extensions": installed_extensions
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze VM extensions for {vm.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Vulnerability Scanner check: {e}")

    return findings