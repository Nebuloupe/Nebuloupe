import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

def run_check(credential):
    """
    Checks if App Services have FTP disabled (or FTPS only).
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
                    
                    try:
                        # Must retrieve the site configuration
                        config = web_client.web_apps.get_configuration(app.resource_group, app.name)
                        ftps_state = getattr(config, 'ftps_state', 'Unknown')
                        
                        if ftps_state.lower() == 'allallowed':
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-9.4", 
                                "check": "App Service FTP Basic Auth Enabled",
                                "severity": "Medium",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "App Service",
                                "resource_type": "Microsoft.Web/sites",
                                "resource_id": app.id,
                                "region": app.location,
                                "description": f"App Service '{app.name}' has standard FTP enabled.",
                                "remediation": "Configure FTPS state to 'FtpsOnly' or 'Disabled'.",
                                "references": ["https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp"],
                                "resource_attributes": {
                                    "app_name": app.name,
                                    "ftps_state": ftps_state
                                },
                                "evidence": {
                                    "ftps_state": ftps_state
                                }
                            })
                    except Exception as e:
                        pass
                        
            except Exception as e:
                pass
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Service FTP check: {e}")

    return findings