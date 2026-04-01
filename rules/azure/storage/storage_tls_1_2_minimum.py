import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.storage import StorageManagementClient

def run_check(credential):
    """
    Checks if Azure Storage Accounts use minimum TLS version of 1.2.
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
                    # Check minimum TLS version
                    min_tls = getattr(account, "minimum_tls_version", None)
                    if min_tls != "TLS1_2":
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.1", # Related to Secure Transfer
                            "check": "Storage Account Minimum TLS Version is below 1.2",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' has minimum TLS version set to {min_tls} instead of at least TLS1_2.",
                            "remediation": "Update the storage account minimum TLS version to 'TLS1_2'.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version"],
                            "resource_attributes": {
                                "minimum_tls_version": str(min_tls)
                            },
                            "evidence": {
                                "minimum_tls_version": str(min_tls)
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-3.1", # Related to Secure Transfer
                            "check": "Storage Account Minimum TLS Version is below 1.2",
                            "severity": "Medium",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Storage",
                            "resource_type": "Microsoft.Storage/storageAccounts",
                            "resource_id": account.id,
                            "region": account.location,
                            "description": f"Storage account '{account.name}' has minimum TLS version correctly set to at least TLS1_2.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version"],
                            "resource_attributes": {
                                "minimum_tls_version": str(min_tls)
                            },
                            "evidence": {
                                "minimum_tls_version": str(min_tls)
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze TLS for storage account {account.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for storage tls check: {e}")

    return findings