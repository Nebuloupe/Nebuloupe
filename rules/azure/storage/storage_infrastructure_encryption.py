import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Storage Accounts have Infrastructure Encryption enabled (Double Encryption).
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
                    # Check infrastructure encryption
                    encryption = getattr(account, "encryption", None)
                    infrastructure_encryption = False
                    
                    if encryption:
                        infrastructure_encryption = getattr(encryption, "require_infrastructure_encryption", False)
                        
                    if not infrastructure_encryption:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.2", # Custom / Extra Security
                            "check": "Storage Account Infrastructure Encryption Not Enabled",
                            "severity": "Low",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' does not have Infrastructure Encryption (Double Encryption) enabled.",
                            "remediation": "Create a new storage account with Infrastructure Encryption enabled (it cannot be enabled after creation).",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/common/infrastructure-encryption-enable"],
                            "resource_attributes": {
                                "require_infrastructure_encryption": bool(infrastructure_encryption)
                            },
                            "evidence": {
                                "require_infrastructure_encryption": bool(infrastructure_encryption)
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze infrastructure encryption for {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for infrastructure encryption check: {e}")

    return findings