import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Azure Storage Accounts have blob versioning enabled.
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
                    # Get resource group from resource ID
                    rg_name = account.id.split('/')[4]

                    # Retrieve blob service properties to check versioning
                    blob_service = storage_client.blob_services.get_service_properties(rg_name, account.name)
                    
                    is_versioning_enabled = getattr(blob_service, 'is_versioning_enabled', False)

                    if not is_versioning_enabled:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.9", # Custom/CIS related
                            "check": "Storage Account Blob Versioning Not Enabled",
                            "severity": "Low",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' does not have blob versioning enabled.",
                            "remediation": "Enable blob versioning in the data protection settings.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-enable"],
                            "resource_attributes": {
                                "is_versioning_enabled": bool(is_versioning_enabled)
                            },
                            "evidence": {
                                "is_versioning_enabled": bool(is_versioning_enabled)
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.9", # Custom/CIS related
                            "check": "Storage Account Blob Versioning Not Enabled",
                            "severity": "Low",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' has blob versioning enabled.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/versioning-enable"],
                            "resource_attributes": {
                                "is_versioning_enabled": bool(is_versioning_enabled)
                            },
                            "evidence": {
                                "is_versioning_enabled": bool(is_versioning_enabled)
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze blob versioning for storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for blob versioning check: {e}")

    return findings