import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Network Watcher is enabled for all regions where resources are deployed.
    Note: Simplistic check to see if at least one Network Watcher exists per subscription/region.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            try:
                # Find all regions with virtual networks
                active_regions = set()
                for vnet in network_client.virtual_networks.list_all():
                    active_regions.add(vnet.location_original_string if hasattr(vnet, 'location_original_string') else vnet.location)
                
                if not active_regions:
                    continue  # No VNets, nothing to monitor
                    
                # Find all network watchers
                watcher_regions = set()
                watchers = list(network_client.network_watchers.list_all())
                for watcher in watchers:
                    if watcher.provisioning_state == "Succeeded":
                        watcher_regions.add(watcher.location)

                # Identify regions missing a network watcher
                missing_regions = active_regions - watcher_regions
                
                if missing_regions:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-6.5",
                        "check": "Network Watcher Enabled",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Network",
                        "resource_type": "Microsoft.Network/networkWatchers",
                        "resource_id": f"/subscriptions/{sub_id}",
                        "region": "global",
                        "description": f"Subscription '{sub_id}' has VNets but no Network Watcher enabled in regions: {missing_regions}.",
                        "remediation": "Enable Network Watcher for the regions where VNets are deployed.",
                        "references": ["https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create"],
                        "resource_attributes": {
                            "subscription_id": sub_id,
                            "missing_watcher_regions": list(missing_regions)
                        },
                        "evidence": {
                            "active_vnet_regions": list(active_regions),
                            "active_network_watcher_regions": list(watcher_regions)
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-6.5",
                        "check": "Network Watcher Enabled",
                        "severity": "Medium",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "Network",
                        "resource_type": "Microsoft.Network/networkWatchers",
                        "resource_id": f"/subscriptions/{sub_id}",
                        "region": "global",
                        "description": f"Subscription '{sub_id}' has Network Watcher enabled in all regions where VNets are deployed.",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-create"],
                        "resource_attributes": {
                            "subscription_id": sub_id,
                            "missing_watcher_regions": []
                        },
                        "evidence": {
                            "active_vnet_regions": list(active_regions),
                            "active_network_watcher_regions": list(watcher_regions)
                        }
                    })
            except Exception as e:
                print(f"       [!] Warning: Could not analyze network watchers for subscription {sub_id}: {e}")
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Network Watcher check: {e}")

    return findings