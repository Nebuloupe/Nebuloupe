import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Virtual Machine Network Interfaces (NICs) have Public IP addresses attached directly.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            for nic in network_client.network_interfaces.list_all():
                try:
                    # NICs can have multiple IP configurations
                    for ip_config in nic.ip_configurations:
                        if getattr(ip_config, 'public_ip_address', None) is not None:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-6.1", # Broadly part of limiting internet attack surface
                                "check": "Virtual Machine NIC has a Public IP Address",
                                "severity": "High",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Network",
                                "resource_type": "Microsoft.Network/networkInterfaces",
                                "resource_id": nic.id,
                                "region": nic.location,
                                "description": f"Network Interface '{nic.name}' has a direct Public IP address assigned.",
                                "remediation": "Remove the Public IP address from the NIC. Route traffic through a Load Balancer, App Gateway, or Azure Firewall instead.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/virtual-network-public-ip-address"],
                                "resource_attributes": {
                                    "nic_name": nic.name,
                                    "ip_config_name": ip_config.name
                                },
                                "evidence": {
                                    "public_ip_id": ip_config.public_ip_address.id
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-6.1", # Broadly part of limiting internet attack surface
                                "check": "Virtual Machine NIC has a Public IP Address",
                                "severity": "High",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "Network",
                                "resource_type": "Microsoft.Network/networkInterfaces",
                                "resource_id": nic.id,
                                "region": nic.location,
                                "description": f"Network Interface '{nic.name}' does not have a direct Public IP address assigned.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/virtual-network-public-ip-address"],
                                "resource_attributes": {
                                    "nic_name": nic.name,
                                    "ip_config_name": ip_config.name
                                },
                                "evidence": {
                                    "public_ip_id": None
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze IP configurations for NIC {nic.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VM Public IP check: {e}")

    return findings