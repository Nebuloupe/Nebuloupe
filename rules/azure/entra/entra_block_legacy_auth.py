import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there is a Conditional Access policy blocking legacy authentication.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            policies = response.json().get('value', [])
            legacy_auth_blocked = False
            
            for policy in policies:
                state = policy.get('state')
                if state == 'enabled':
                    client_apps = policy.get('conditions', {}).get('clientApplications', {}).get('includeClientApplications', [])
                    controls = policy.get('grantControls', {}).get('builtInControls', [])
                    
                    if ('exchangeActiveSync' in client_apps or 'other' in client_apps) and 'block' in controls:
                        legacy_auth_blocked = True
                        break
                        
            if not legacy_auth_blocked:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.12",
                    "check": "Block Legacy Authentication using Conditional Access",
                    "severity": "High",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "No active Conditional Access policy blocks legacy authentication methods.",
                    "remediation": "Create a Conditional Access policy blocking legacy client apps (Exchange ActiveSync, Other clients).",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"],
                    "resource_attributes": {
                        "legacy_auth_blocked": False
                    },
                    "evidence": {
                        "policies_evaluated": len(policies)
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_block_legacy_auth check: {e}")

    return findings