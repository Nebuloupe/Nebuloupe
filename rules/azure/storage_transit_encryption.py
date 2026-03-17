import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Azure Storage Accounts require secure transfer (HTTPS).
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
                    is_https_only = account.enable_https_traffic_only
                    
                    if not is_https_only:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.1",
                            "check": "Storage Transit Encryption Not Required",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' does not require secure transfer (HTTPS).",
                            "remediation": "Enable 'Secure transfer required' on the storage account.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"],
                            "resource_attributes": {
                                "enable_https_traffic_only": False
                            },
                            "evidence": {
                                "enable_https_traffic_only": False
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for transit encryption rule: {e}")

    return findings
