import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Virtual Network Peerings are overly permissive (Allowing forwarded traffic unnecessarily).
    Note: 'allow_forwarded_traffic' allows traffic not originating from the peered VNet to flow through it.
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
                    for peering in getattr(vnet, 'virtual_network_peerings', []):
                        allow_forwarded = getattr(peering, 'allow_forwarded_traffic', False)
                        
                        # In many secure architectures, you only want resources in peered VNets to talk directly.
                        # Forwarded traffic indicates routing through appliances/hubs which might be intended,
                        # but it's worth flagging as a potential open pivot if not managed.
                        if allow_forwarded:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-6.X",
                                "check": "VNet Peering allows forwarded traffic",
                                "severity": "Low", # Informational/Low complexity
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Network",
                                "resource_type": "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
                                "resource_id": peering.id,
                                "region": vnet.location,
                                "description": f"VNet peering '{peering.name}' on VNet '{vnet.name}' has 'Allow forwarded traffic' enabled.",
                                "remediation": "Review the peering architecture. If not acting as a Hub/Spoke requiring NVA transit, disable forwarded traffic.",
                                "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-peering-overview"],
                                "resource_attributes": {
                                    "peering_name": peering.name,
                                    "allow_forwarded_traffic": True
                                },
                                "evidence": {
                                    "remote_virtual_network": peering.remote_virtual_network.id if getattr(peering, 'remote_virtual_network', None) else "unknown"
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze VNet peerings for {vnet.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for VNet peering check: {e}")

    return findings