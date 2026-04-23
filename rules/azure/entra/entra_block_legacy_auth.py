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
    Checks if there is a Conditional Access policy blocking legacy authentication.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        security_defaults_state = _get_security_defaults_state(headers)
        security_defaults_enabled = security_defaults_state["enabled"]
        security_defaults_verified = security_defaults_state["verified"]
        security_defaults_status_code = security_defaults_state["status_code"]
        
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

            if security_defaults_verified:
                fail_description = "No active Conditional Access policy blocks legacy authentication methods, and Security Defaults are not enabled."
                fail_remediation = "Enable Security Defaults or create a Conditional Access policy blocking legacy client apps (Exchange ActiveSync, Other clients)."
            else:
                fail_description = "No active Conditional Access policy blocks legacy authentication methods, and Security Defaults could not be verified (Graph API access denied or unavailable)."
                fail_remediation = "Grant Graph permission to read Security Defaults (for example Policy.Read.All) and/or create a Conditional Access policy blocking legacy client apps (Exchange ActiveSync, Other clients)."
                        
            if not legacy_auth_blocked and not security_defaults_enabled:
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
                    "description": fail_description,
                    "remediation": fail_remediation,
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"],
                    "resource_attributes": {
                        "legacy_auth_blocked": False,
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "policies_evaluated": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
            else:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.12",
                    "check": "Block Legacy Authentication using Conditional Access",
                    "severity": "High",
                    "status": "PASS",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "Legacy authentication protections are covered by Conditional Access policy or Security Defaults.",
                    "remediation": "No action required.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication"],
                    "resource_attributes": {
                        "legacy_auth_blocked": legacy_auth_blocked,
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "policies_evaluated": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_block_legacy_auth check: {e}")

    return findings