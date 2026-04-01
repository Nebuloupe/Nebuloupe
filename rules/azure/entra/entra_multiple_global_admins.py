import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there are between two and five Global Administrators.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        role_url = "https://graph.microsoft.com/v1.0/directoryRoles?$filter=displayName eq 'Global Administrator'"
        role_resp = requests.get(role_url, headers=headers)
        
        if role_resp.status_code == 200:
            roles = role_resp.json().get('value', [])
            if roles:
                role_id = roles[0]['id']
                members_url = f"https://graph.microsoft.com/v1.0/directoryRoles/{role_id}/members"
                members_resp = requests.get(members_url, headers=headers)
                
                if members_resp.status_code == 200:
                    members = members_resp.json().get('value', [])
                    
                    # Count users (ignoring service principals)
                    admins_count = len([m for m in members if m.get('@odata.type') == '#microsoft.graph.user'])
                    
                    if admins_count < 2 or admins_count > 5:
                        findings.append({
                            "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-Azure-1.3",
                            "check": "Ensure there are between two and five Global Administrators",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Identity",
                            "resource_type": "azure_entra_tenant",
                            "resource_id": "tenant",
                            "region": "global",
                            "description": f"Found {admins_count} Global Administrators. Recommended is between 2 and 5.",
                            "remediation": "Adjust the number of assigned Global Administrators to improve security posture.",
                            "references": ["https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning"],
                            "resource_attributes": {
                                "global_admin_count": admins_count
                            },
                            "evidence": {
                                "global_admin_count": admins_count
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-Azure-1.3",
                            "check": "Ensure there are between two and five Global Administrators",
                            "severity": "Medium",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "Identity",
                            "resource_type": "azure_entra_tenant",
                            "resource_id": "tenant",
                            "region": "global",
                            "description": f"Found {admins_count} Global Administrators. Recommended is between 2 and 5.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/active-directory/roles/security-planning"],
                            "resource_attributes": {
                                "global_admin_count": admins_count
                            },
                            "evidence": {
                                "global_admin_count": admins_count
                            }
                        })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_multiple_global_admins check: {e}")

    return findings