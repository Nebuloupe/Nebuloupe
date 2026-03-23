import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient

def run_check(credential):
    findings = []
    try:
        sub_client = SubscriptionClient(credential)
        sub_id = list(sub_client.subscriptions.list())[0].subscription_id
        monitor_client = MonitorManagementClient(credential, sub_id)
        kv_client = KeyVaultManagementClient(credential, sub_id)
        
        try:
            vaults = kv_client.vaults.list()
            for vault in vaults:
                resource_uri = vault.id
                diagnostics = list(monitor_client.diagnostic_settings.list(resource_uri=resource_uri))
                
                # Check if there is any diagnostics setting that enables AuditEvent logs
                logs_enabled = False
                for diag in diagnostics:
                    for log in diag.logs:
                        if log.category == "AuditEvent" and log.enabled:
                            logs_enabled = True
                            break
                    if logs_enabled:
                        break

                if not logs_enabled:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-5.1.7",
                        "check": "Key Vault Logging Not Enabled",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Key Vault",
                        "resource_type": "Microsoft.KeyVault/vaults",
                        "resource_id": vault.id,
                        "region": vault.location,
                        "description": f"Key Vault '{vault.name}' does not have AuditEvent diagnostic logs enabled.",
                        "remediation": "Enable diagnostic settings with 'AuditEvent' logs mapped to a Log Analytics workspace.",
                        "references": ["https://learn.microsoft.com/en-us/azure/key-vault/general/logging"],
                        "resource_attributes": {
                            "vault_name": vault.name,
                            "logs_enabled": False
                        },
                        "evidence": {
                            "logs_enabled": False
                        }
                    })
        except Exception as e:
            pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Key Vault Diagnostics check: {e}")
    return findings
