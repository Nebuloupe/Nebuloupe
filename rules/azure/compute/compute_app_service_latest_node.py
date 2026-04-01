import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

def run_check(credential):
    """
    Checks if App Services are using latest Node.js version.
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
                        node_version = getattr(config, 'node_version', '')
                        
                        # Simplified check; versions less than 18 could be a finding
                        if node_version and (node_version.startswith('10') or node_version.startswith('12') or node_version.startswith('14') or node_version.startswith('16') or 'LTS' not in node_version):
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-9.8", 
                                "check": "App Service Outdated Node.js Version",
                                "severity": "Medium",
                                "status": "FAIL",
                                "cloud_provider": "azure",
                                "category": "App Service",
                                "resource_type": "Microsoft.Web/sites",
                                "resource_id": app.id,
                                "region": app.location,
                                "description": f"App Service '{app.name}' is running an outdated or non-LTS Node.js version ({node_version}).",
                                "remediation": "Update the App Service to use the latest LTS Node.js version.",
                                "references": ["https://learn.microsoft.com/en-us/azure/app-service/configure-language-nodejs"],
                                "resource_attributes": {
                                    "app_name": app.name,
                                    "node_version": node_version
                                },
                                "evidence": {
                                    "node_version": node_version
                                }
                            })
                        else:
                            findings.append({
                                "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                "rule_id": "CIS-AZURE-9.8", 
                                "check": "App Service Outdated Node.js Version",
                                "severity": "Medium",
                                "status": "PASS",
                                "cloud_provider": "azure",
                                "category": "App Service",
                                "resource_type": "Microsoft.Web/sites",
                                "resource_id": app.id,
                                "region": app.location,
                                "description": f"App Service '{app.name}' is running a supported Node.js version or it is disabled.",
                                "remediation": "No action required.",
                                "references": ["https://learn.microsoft.com/en-us/azure/app-service/configure-language-nodejs"],
                                "resource_attributes": {
                                    "app_name": app.name,
                                    "node_version": node_version
                                },
                                "evidence": {
                                    "node_version": node_version
                                }
                            })
                    except Exception as e:
                        pass
                        
            except Exception as e:
                pass
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Service Node.js check: {e}")

    return findings