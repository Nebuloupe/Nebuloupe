import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

def run_check(credential):
    """
    Checks if App Services are using latest PHP version.
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
                        config = web_client.web_apps.get_configuration(app.resource_group, app.name)
                        php_version = getattr(config, 'php_version', '')
                        
                        # Empty string means disabled
                        if php_version and php_version not in ['8.0', '8.1', '8.2', '8.3']:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-9.7", 
                                "check": "App Service Outdated PHP Version",
                                "severity": "Medium",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "App Service",
                                "resource_type": "Microsoft.Web/sites",
                                "resource_id": app.id,
                                "region": app.location,
                                "description": f"App Service '{app.name}' is running an outdated PHP version ({php_version}).",
                                "remediation": "Update the App Service to use the latest supported PHP version.",
                                "references": ["https://learn.microsoft.com/en-us/azure/app-service/configure-language-php"],
                                "resource_attributes": {
                                    "app_name": app.name,
                                    "php_version": php_version
                                },
                                "evidence": {
                                    "php_version": php_version
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-9.7", 
                                "check": "App Service Outdated PHP Version",
                                "severity": "Medium",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "App Service",
                                "resource_type": "Microsoft.Web/sites",
                                "resource_id": app.id,
                                "region": app.location,
                                "description": f"App Service '{app.name}' is running a supported PHP version or PHP is disabled.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/app-service/configure-language-php"],
                                "resource_attributes": {
                                    "app_name": app.name,
                                    "php_version": php_version
                                },
                                "evidence": {
                                    "php_version": php_version
                                }
                            })
                    except Exception as e:
                        pass
                        
            except Exception as e:
                pass
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Service PHP check: {e}")

    return findings