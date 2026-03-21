import uuid
import requests

def run_check(credential, subscription_id=None, **kwargs):
    """
    Checks if users are allowed to consent to third-party applications accessing company data.
    """
    findings = []
    try:
        token_info = credential.get_token('https://graph.microsoft.com/.default')
        headers = {
            'Authorization': f'Bearer {token_info.token}',
            'Content-Type': 'application/json'
        }
        
        # Checking default user consent policy configuration
        url = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            policy = response.json()
            granted_policies = policy.get('permissionGrantPolicyIdsAssignedToDefaultUserRole', [])
            
            # Legacy default allows arbitrary user consent
            if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in granted_policies:
                findings.append({
                    "finding_id": f"NL-AZURE-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-Azure-1.18",
                    "check": "Ensure user consent to apps accessing company data is disabled",
                    "severity": "Medium",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Identity",
                    "resource_type": "azure_entra_tenant",
                    "resource_id": "tenant",
                    "region": "global",
                    "description": "Users are allowed to consent to third-party applications accessing company data on their behalf.",
                    "remediation": "Disable user consent capability in Azure AD Enterprise Applications settings.",
                    "references": ["https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent"],
                    "resource_attributes": {
                        "allowed_consent_policies": granted_policies
                    },
                    "evidence": {
                        "permissionGrantPolicyIdsAssignedToDefaultUserRole": granted_policies
                    }
                })
    except Exception as e:
        print(f"       [!] Warning: Exception in entra_user_consent_disabled check: {e}")

    return findings