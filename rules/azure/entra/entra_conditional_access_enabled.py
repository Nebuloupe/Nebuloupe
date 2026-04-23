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
    Checks if there are any active Conditional Access Policies.
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
            active_policies = [p for p in policies if p.get('state') == 'enabled']

            if security_defaults_verified:
                fail_description = "Tenant has zero active Conditional Access policies and Security Defaults are not enabled."
                fail_remediation = "Enable Security Defaults or baseline Conditional Access policies to secure the tenant and resources."
            else:
                fail_description = "Tenant has zero active Conditional Access policies, and Security Defaults could not be verified (Graph API access denied or unavailable)."
                fail_remediation = "Grant Graph permission to read Security Defaults (for example Policy.Read.All) and/or enable baseline Conditional Access policies."
            
            if len(active_policies) == 0 and not security_defaults_enabled:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.1",
                    "check": "Conditional Access Policies Enabled",
                    "severity": "Critical",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": fail_description,
                    "remediation": fail_remediation,
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"],
                    "resource_attributes": {
                        "active_policies_count": 0,
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "total_policies_found": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
            else:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.1",
                    "check": "Conditional Access Policies Enabled",
                    "severity": "Critical",
                    "status": "PASS",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": f"Tenant controls are present via {len(active_policies)} active Conditional Access policies or Security Defaults.",
                    "remediation": "No action required.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"],
                    "resource_attributes": {
                        "active_policies_count": len(active_policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified
                    },
                    "evidence": {
                        "total_policies_found": len(policies),
                        "security_defaults_enabled": security_defaults_enabled,
                        "security_defaults_verified": security_defaults_verified,
                        "security_defaults_status_code": security_defaults_status_code
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_conditional_access_enabled check: {e}")

    return findings