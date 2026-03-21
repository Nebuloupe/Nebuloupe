import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there is a Conditional Access Policy enforcing MFA for All Users in Azure AD/Entra ID.
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
            mfa_enforced_all = False
            
            for policy in policies:
                # Check active policies requiring MFA
                state = policy.get('state')
                controls = policy.get('grantControls', {}).get('builtInControls', [])
                if state == 'enabled' and 'mfa' in controls:
                    # Look for universal application
                    include_users = policy.get('conditions', {}).get('users', {}).get('includeUsers', [])
                    if 'All' in include_users:
                        mfa_enforced_all = True
                        break
                        
            if not mfa_enforced_all:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.2",
                    "check": "MFA should be enabled for all users",
                    "severity": "High",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "No active Conditional Access policy enforces MFA for *All* users.",
                    "remediation": "Create a Conditional Access policy requiring MFA for all users.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa"],
                    "resource_attributes": {
                        "mfa_enforced_all": False
                    },
                    "evidence": {
                        "policies_found": len(policies)
                    }
                })
        else:
            print(f"       [!] Warning: Graph API error extracting All Users MFA: {response.text}")
            
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_mfa_all_users check: {e}")

    return findings