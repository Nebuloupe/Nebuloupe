import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if Identity Protection risk policies (Sign-in or User Risk) are configured.
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
            risk_policies_active = False
            
            for policy in policies:
                if policy.get('state') == 'enabled':
                    cond = policy.get('conditions', {})
                    user_risk = cond.get('userRiskLevels', [])
                    sign_in_risk = cond.get('signInRiskLevels', [])
                    
                    if user_risk or sign_in_risk:
                        risk_policies_active = True
                        break
                        
            if not risk_policies_active:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.14",
                    "check": "Ensure Identity Protection risk policies are active",
                    "severity": "High",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "No active Conditional Access policies found enforcing user or sign-in risk levels.",
                    "remediation": "Create Conditional Access policies to mitigate Identity Protection risk events.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies"],
                    "resource_attributes": {
                        "risk_policies_enabled": False
                    },
                    "evidence": {
                        "policies_evaluated": len(policies)
                    }
                })
            else:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.14",
                    "check": "Ensure Identity Protection risk policies are active",
                    "severity": "High",
                    "status": "PASS",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "Active Conditional Access policies are enforcing user or sign-in risk levels.",
                    "remediation": "No action required.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/howto-identity-protection-configure-risk-policies"],
                    "resource_attributes": {
                        "risk_policies_enabled": True
                    },
                    "evidence": {
                        "policies_evaluated": len(policies)
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_risk_policies_active check: {e}")

    return findings