import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Virtual Networks containing workloads have a Bastion Host deployed for secure access.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            for vnet in network_client.virtual_networks.list_all():
                try:
                    # Check if 'AzureBastionSubnet' exists within the VNet
                    has_bastion_subnet = False
                    subnets = getattr(vnet, 'subnets', [])
                    for subnet in subnets:
                        if subnet.name == "AzureBastionSubnet":
                            has_bastion_subnet = True
                            break
                            
                    if not has_bastion_subnet:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-6.X",
                            "check": "Azure Bastion Host is not deployed in Virtual Network",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Network",
                            "resource_type": "Microsoft.Network/virtualNetworks",
                            "resource_id": vnet.id,
                            "region": vnet.location,
                            "description": f"Virtual Network '{vnet.name}' does not contain an 'AzureBastionSubnet', indicating no Bastion host is deployed for secure remote access.",
                            "remediation": "Deploy Azure Bastion to enable secure RDP and SSH connectivity without exposing VMs to the internet.",
                            "references": ["https://learn.microsoft.com/en-us/azure/bastion/bastion-overview"],
                            "resource_attributes": {
                                "vnet_name": vnet.name,
                                "has_bastion_subnet": False
                            },
                            "evidence": {
                                "subnet_names": [s.name for s in subnets]
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze Bastion subnets for VNet {vnet.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Bastion Host check: {e}")

    return findings