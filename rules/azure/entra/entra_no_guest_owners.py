import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there are any guest users with the Global Administrator role.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        # Checking if any guest users are assigned to Global Administrator
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
                    guests = [m for m in members if m.get('userType') == 'Guest']
                    
                    if guests:
                        findings.append({
                            "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-Azure-1.4",
                            "check": "No Guest Users have Global Administrator role",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Identity",
                            "resource_type": "azure_entra_tenant",
                            "resource_id": "tenant",
                            "region": "global",
                            "description": f"Found {len(guests)} guest user(s) with Global Administrator privileges.",
                            "remediation": "Remove Global Administrator role from guest accounts.",
                            "references": ["https://learn.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions"],
                            "resource_attributes": {
                                "guest_global_admins": len(guests)
                            },
                            "evidence": {
                                "guest_users": [g.get('userPrincipalName') for g in guests]
                            }
                        })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_no_guest_owners check: {e}")

    return findings