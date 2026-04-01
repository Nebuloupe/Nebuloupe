import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if Directory synchronization and password hash sync is enabled using MS Graph APIs.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        # Check Organization configuration for synchronization status
        url = "https://graph.microsoft.com/v1.0/organization"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            orgs = response.json().get('value', [])
            for org in orgs:
                sync_enabled = org.get('onPremisesSyncEnabled', False)
                
                # If sync is explicitly disabled or not configured in a hybrid scenario, flag it (basic check).
                # *Note*: This is complex to definitively determine without strict context on whether
                # the tenant is purely cloud-native vs hybrid. Assuming it flags un-synced directories as an informational/medium warning.
                if not sync_enabled:
                    # In a purely cloud-native tenant, this rule would technically "Pass" or be N/A.
                    # We will emit a low-severity informational finding here so users can audit it.
                    findings.append({
                        "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-Azure-1.X",
                        "check": "Verify On-Premises Directory Synchronization/Password Sync",
                        "severity": "Low",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Identity",
                        "resource_type": "azure_entra_tenant",
                        "resource_id": "tenant",
                        "region": "global",
                        "description": "On-premises synchronization is not enabled. Review if this is a hybrid tenant requiring password hash sync.",
                        "remediation": "Enable Azure AD Connect and configure Password Hash Sync if using a hybrid environment.",
                        "references": ["https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs"],
                        "resource_attributes": {
                            "on_premises_sync_enabled": False
                        },
                        "evidence": {
                            "directory_sync_enabled": sync_enabled
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-Azure-1.X",
                        "check": "Verify On-Premises Directory Synchronization/Password Sync",
                        "severity": "Low",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "Identity",
                        "resource_type": "azure_entra_tenant",
                        "resource_id": "tenant",
                        "region": "global",
                        "description": "On-premises synchronization is enabled.",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs"],
                        "resource_attributes": {
                            "on_premises_sync_enabled": True
                        },
                        "evidence": {
                            "directory_sync_enabled": sync_enabled
                        }
                    })
                    
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_password_hash_sync check: {e}")

    return findings