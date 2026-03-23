import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Network Security Group (NSG) Flow Logs are enabled on Network Watchers.
    Note: A full thorough check would iterate every NSG and verify a flow log targets it. 
    This approximates by checking if flow logs exist under Network Watchers.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            try:
                # Get all Network Security Groups to verify coverage
                nsgs = list(network_client.network_security_groups.list_all())
                nsg_ids = set([nsg.id for nsg in nsgs])
                
                # Get all flow logs configured in Network Watchers
                flow_logs = list(network_client.flow_logs.list_all())
                covered_nsg_ids = set([f.target_resource_id for f in flow_logs if getattr(f, 'enabled', False)])
                
                # Find NSGs missing flow logs
                missing_nsgs = nsg_ids - covered_nsg_ids
                
                if missing_nsgs:
                    # Emitting one finding per subscription instead of per NSG to group the noise
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-6.4", # Related to logging network traffic
                        "check": "NSG Flow Logs are not enabled for all NSGs",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Network",
                        "resource_type": "Microsoft.Network/networkSecurityGroups",
                        "resource_id": f"/subscriptions/{sub_id}",
                        "region": "global",
                        "description": f"Found {len(missing_nsgs)} Network Security Group(s) that do not have active Flow Logs configured in Network Watcher.",
                        "remediation": "Enable Network Watcher Flow Logs for all Network Security Groups.",
                        "references": ["https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-portal"],
                        "resource_attributes": {
                            "total_nsgs": len(nsg_ids),
                            "nsgs_without_flow_logs": len(missing_nsgs)
                        },
                        "evidence": {
                            "uncovered_nsg_count": len(missing_nsgs)
                        }
                    })
            except Exception as e:
                print(f"       [!] Warning: Could not analyze NSG Flow logs for subscription {sub_id}: {e}")
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for NSG Flow Logs check: {e}")

    return findings