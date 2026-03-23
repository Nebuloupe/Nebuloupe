import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there is a Conditional Access Policy enforcing MFA for Admins in Azure AD/Entra ID.
    """
    findings = []
    
    try:
        # Get Microsoft Graph API access token from the credential
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        # Query Conditional Access Policies
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            policies = response.json().get('value', [])
            mfa_enforced_for_admins = False
            
            for policy in policies:
                # Check active policies requiring MFA
                state = policy.get('state')
                controls = policy.get('grantControls', {}).get('builtInControls', [])
                if state == 'enabled' and 'mfa' in controls:
                    # Look if it applies to roles/admins
                    users_cond = policy.get('conditions', {}).get('users', {})
                    include_roles = users_cond.get('includeRoles', [])
                    if include_roles:
                        mfa_enforced_for_admins = True
                        break
                        
            if not mfa_enforced_for_admins:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.1",
                    "check": "MFA should be enabled for all privileged accounts",
                    "severity": "Critical",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "No active Conditional Access policy enforces MFA for administrators/roles.",
                    "remediation": "Create a Conditional Access policy enforcing MFA for all privileged roles.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa"],
                    "resource_attributes": {
                        "mfa_enforced_for_admins": False
                    },
                    "evidence": {
                        "policies_found": len(policies)
                    }
                })
        else:
            print(f"       [!] Warning: Graph API error extracting Admin MFA: {response.text}")
            
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_mfa_admins_enforced check: {e}")

    return findings