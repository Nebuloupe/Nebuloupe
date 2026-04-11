import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Azure Storage Accounts have soft delete enabled for blobs.
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

                    # Retrieve blob service properties to check soft delete
                    blob_service = storage_client.blob_services.get_service_properties(rg_name, account.name)
                    
                    soft_delete_enabled = False
                    if hasattr(blob_service, 'delete_retention_policy') and blob_service.delete_retention_policy:
                        soft_delete_enabled = blob_service.delete_retention_policy.enabled

                    if not soft_delete_enabled:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.8",
                            "check": "Storage Account Soft Delete Not Enabled for Blobs",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' does not have soft delete enabled for blobs.",
                            "remediation": "Enable soft delete for blobs in the data protection settings.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"],
                            "resource_attributes": {
                                "blob_soft_delete_enabled": False
                            },
                            "evidence": {
                                "blob_soft_delete_enabled": False
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.8",
                            "check": "Storage Account Soft Delete Not Enabled for Blobs",
                            "severity": "Medium",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' has soft delete enabled for blobs.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/soft-delete-blob-overview"],
                            "resource_attributes": {
                                "blob_soft_delete_enabled": True
                            },
                            "evidence": {
                                "blob_soft_delete_enabled": True
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze soft delete for storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for soft delete check: {e}")

    return findings