import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if there are highly-privileged broad custom roles.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            roles = response.json().get('value', [])
            for role in roles:
                if not role.get('isBuiltIn'):
                    permissions = role.get('rolePermissions', [])
                    for perm in permissions:
                        allowed = perm.get('allowedResourceActions', [])
                        # Look for excessive broad directory level assignments
                        if 'microsoft.directory/*' in allowed or '*' in allowed:
                            findings.append({
                                "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-Azure-1.16",
                                "check": "No Custom Role contains root/super-admin broad privileges",
                                "severity": "High",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "Identity",
                                "resource_type": "azure_entra_role",
                                "resource_id": role.get('id', 'unknown'),
                                "region": "global",
                                "description": f"Custom role '{role.get('displayName')}' contains root level permissions ({allowed}).",
                                "remediation": "Review custom role permissions and apply principle of least privilege.",
                                "references": ["https://learn.microsoft.com/en-us/azure/active-directory/roles/custom-overview"],
                                "resource_attributes": {
                                    "role_name": role.get('displayName'),
                                    "is_built_in": False
                                },
                                "evidence": {
                                    "allowed_actions": allowed
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-Azure-1.16",
                                "check": "No Custom Role contains root/super-admin broad privileges",
                                "severity": "High",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "Identity",
                                "resource_type": "azure_entra_role",
                                "resource_id": role.get('id', 'unknown'),
                                "region": "global",
                                "description": f"Custom role '{role.get('displayName')}' does not contain root level permissions.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/active-directory/roles/custom-overview"],
                                "resource_attributes": {
                                    "role_name": role.get('displayName'),
                                    "is_built_in": False
                                },
                                "evidence": {
                                    "allowed_actions": allowed
                                }
                            })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_custom_role_no_root check: {e}")

    return findings