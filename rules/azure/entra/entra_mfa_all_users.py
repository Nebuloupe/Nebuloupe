import uuid
import requests


def _get_security_defaults_state(headers):
    url = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return {
                "enabled": bool(response.json().get("isEnabled", False)),
                "verified": True,
                "status_code": response.status_code,
            }
        return {
            "enabled": False,
            "verified": False,
            "status_code": response.status_code,
        }
    except Exception:
        return {
            "enabled": False,
            "verified": False,
            "status_code": None,
        }

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
        security_defaults_state = _get_security_defaults_state(headers)
        security_defaults_enabled = security_defaults_state["enabled"]
        security_defaults_verified = security_defaults_state["verified"]
        security_defaults_status_code = security_defaults_state["status_code"]
        
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

            if security_defaults_verified:
                fail_description = "No active Conditional Access policy enforces MFA for *All* users, and Security Defaults are not enabled."
                fail_remediation = "Enable Security Defaults or create a Conditional Access policy requiring MFA for all users."
            else:
                fail_description = "No active Conditional Access policy enforces MFA for *All* users, and Security Defaults could not be verified (Graph API access denied or unavailable)."
                fail_remediation = "Grant Graph permission to read Security Defaults (for example Policy.Read.All) and/or create a Conditional Access policy requiring MFA for all users."
                        
            if not mfa_enforced_all and not security_defaults_enabled:
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
                    "description": fail_description,
                    "remediation": fail_remediation,
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa"],
                    "resource_attributes": {
                        "mfa_enforced_all": False,
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "policies_found": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
            else:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.2",
                    "check": "MFA should be enabled for all users",
                    "severity": "High",
                    "status": "PASS",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "MFA for all users is covered by Conditional Access policy or Security Defaults.",
                    "remediation": "No action required.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-all-users-mfa"],
                    "resource_attributes": {
                        "mfa_enforced_all": mfa_enforced_all,
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "policies_found": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
        else:
            print(f"       [!] Warning: Graph API error extracting All Users MFA: {response.text}")
            
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_mfa_all_users check: {e}")

    return findings