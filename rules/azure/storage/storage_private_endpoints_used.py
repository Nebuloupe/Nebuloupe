import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Storage Accounts have private endpoint connections enabled.
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
                    # Check for private endpoints
                    private_endpoints = getattr(account, "private_endpoint_connections", [])
                    has_private_endpoints = bool(private_endpoints and len(private_endpoints) > 0)
                    
                    if not has_private_endpoints:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.11",
                            "check": "Storage Account does not use Private Endpoints",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' is not configured to use any Private Endpoints.",
                            "remediation": "Create a Private Endpoint for the storage account to ensure traffic stays on the Microsoft backbone network.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints"],
                            "resource_attributes": {
                                "has_private_endpoint_connections": has_private_endpoints
                            },
                            "evidence": {
                                "has_private_endpoint_connections": has_private_endpoints
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze private endpoints for {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for private endpoints check: {e}")

    return findings