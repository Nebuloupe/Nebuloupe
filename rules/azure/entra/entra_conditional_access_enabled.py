import uuid
import requests

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
        
        url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            policies = response.json().get('value', [])
            active_policies = [p for p in policies if p.get('state') == 'enabled']
            
            if len(active_policies) == 0:
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
                    "description": "Tenant has zero active Conditional Access policies enforcing security boundaries.",
                    "remediation": "Enable baseline Conditional Access policies to secure the tenant and resources.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"],
                    "resource_attributes": {
                        "active_policies_count": 0
                    },
                    "evidence": {
                        "total_policies_found": len(policies)
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
                    "description": f"Tenant has {len(active_policies)} active Conditional Access policies.",
                    "remediation": "No action required.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview"],
                    "resource_attributes": {
                        "active_policies_count": len(active_policies)
                    },
                    "evidence": {
                        "total_policies_found": len(policies)
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_conditional_access_enabled check: {e}")

    return findings