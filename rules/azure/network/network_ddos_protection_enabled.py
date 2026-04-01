import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Virtual Networks have DDoS Protection Standard enabled.
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
                    ddos_protection = getattr(vnet, "enable_ddos_protection", False)
                    if not ddos_protection:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-6.6",
                            "check": "DDoS Protection Standard not Enabled on VNet",
                            "severity": "Low",    # Note: Often a costly feature, flagged as Low/Medium to avoid false high urgency for non-prod
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Network",
                            "resource_type": "Microsoft.Network/virtualNetworks",
                            "resource_id": vnet.id,
                            "region": vnet.location,
                            "description": f"Virtual Network '{vnet.name}' does not have Standard DDoS Protection enabled.",
                            "remediation": "Enable DDoS Protection Standard on the Virtual Network if running production workloads.",
                            "references": ["https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"],
                            "resource_attributes": {
                                "enable_ddos_protection": False
                            },
                            "evidence": {
                                "vnet_name": vnet.name,
                                "ddos_protection_enabled": False
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-6.6",
                            "check": "DDoS Protection Standard not Enabled on VNet",
                            "severity": "Low",    # Note: Often a costly feature, flagged as Low/Medium to avoid false high urgency for non-prod
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Network",
                            "resource_type": "Microsoft.Network/virtualNetworks",
                            "resource_id": vnet.id,
                            "region": vnet.location,
                            "description": f"Virtual Network '{vnet.name}' has Standard DDoS Protection enabled.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/ddos-protection/manage-ddos-protection"],
                            "resource_attributes": {
                                "enable_ddos_protection": True
                            },
                            "evidence": {
                                "vnet_name": vnet.name,
                                "ddos_protection_enabled": True
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze DDoS Protection for VNet {vnet.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for DDoS Protection check: {e}")

    return findings