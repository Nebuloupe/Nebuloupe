import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Storage Accounts explicitly allow Trusted Microsoft Services to bypass firewall rules.
    """
    findings = []

    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            storage_client = StorageManagementClient(credential, sub_id)

            for account in storage_client.storage_accounts.list():
                try:
                    # Check network rule set
                    network_rules = getattr(account, "network_rule_set", None)
                    if network_rules and getattr(network_rules, "default_action", "Allow") == "Deny":
                        bypass = getattr(network_rules, "bypass", "")
                        
                        # Sometimes bypass is returned as an enum or list of strings
                        bypass_str = str(bypass).lower()
                        
                        if "azureservices" not in bypass_str:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-3.7",
                                "check": "Storage Account does not allow Trusted Microsoft Services",
                                "severity": "Medium",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Storage/storageAccounts",
                                "resource_id": account.id,
                                "region": account.location,
                                "description": f"Storage account '{account.name}' has a firewall but does not allow Trusted Microsoft Services to bypass it.",
                                "remediation": "Update the storage account's network routing to allow 'AzureServices' in the bypass list.",
                                "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security#exceptions"],
                                "resource_attributes": {
                                    "network_bypass": bypass_str
                                },
                                "evidence": {
                                    "network_bypass": bypass_str
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-3.7",
                                "check": "Storage Account does not allow Trusted Microsoft Services",
                                "severity": "Medium",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Storage/storageAccounts",
                                "resource_id": account.id,
                                "region": account.location,
                                "description": f"Storage account '{account.name}' allows Trusted Microsoft Services to bypass its firewall.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security#exceptions"],
                                "resource_attributes": {
                                    "network_bypass": bypass_str
                                },
                                "evidence": {
                                    "network_bypass": bypass_str
                                }
                            })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze network rules for storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for trusted ms services check: {e}")

    return findings