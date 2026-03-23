import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Azure Storage Accounts or specific Blob Containers allow anonymous public access.
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
                    # 1. Check account-level setting
                    # If this is enabled, it allows containers to be made public
                    if getattr(account, "allow_blob_public_access", False):
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.6",
                            "check": "Storage Account Allows Public Access",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' permits public access to blob containers.",
                            "remediation": "Disable 'Allow Blob public access' at the storage account level.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"],
                            "resource_attributes": {
                                "allow_blob_public_access": True
                            },
                            "evidence": {
                                "allow_blob_public_access": True
                            }
                        })
                    
                    # 2. Extract resource group from the account ID to check individual containers
                    # ID format: /subscriptions/.../resourceGroups/<rg_name>/providers/Microsoft.Storage/storageAccounts/...
                    rg_name = account.id.split('/')[4]
                    
                    containers = storage_client.blob_containers.list(rg_name, account.name)
                    for container in containers:
                        access_level = getattr(container, "public_access", "None")
                        if access_level and access_level != "None":
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-3.6.C",
                                "check": "Blob Container is Public",
                                "severity": "Critical",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Storage",
                                "resource_type": "Microsoft.Storage/storageAccounts/blobServices/containers",
                                "resource_id": container.id,
                                "region": account.location,
                                "description": f"Container '{container.name}' in account '{account.name}' is publicly accessible (Level: {access_level}).",
                                "remediation": "Change container access level to 'Private' (no anonymous access).",
                                "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure"],
                                "resource_attributes": {
                                    "public_access": str(access_level)
                                },
                                "evidence": {
                                    "public_access": str(access_level)
                                }
                            })

                except Exception as e:
                    print(f"       [!] Warning: Could not analyze containers for storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for public blob check: {e}")

    return findings
