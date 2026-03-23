import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

def run_check(credential):
    """
    Checks if App Services enforce HTTPS Only.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            try:
                web_client = WebSiteManagementClient(credential, sub_id)
                for app in web_client.web_apps.list():
                    https_only = getattr(app, 'https_only', False)
                    
                    if not https_only:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-9.1", 
                            "check": "App Service HTTPS Only Disabled",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "App Service",
                            "resource_type": "Microsoft.Web/sites",
                            "resource_id": app.id,
                            "region": app.location,
                            "description": f"App Service '{app.name}' does not enforce HTTPS Only.",
                            "remediation": "Enable HTTPS Only in the App Service configuration.",
                            "references": ["https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https"],
                            "resource_attributes": {
                                "app_name": app.name,
                                "https_only": https_only
                            },
                            "evidence": {
                                "https_only": https_only
                            }
                        })
            except Exception as e:
                pass # Probably not registered or no access
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Service HTTPS check: {e}")

    return findings