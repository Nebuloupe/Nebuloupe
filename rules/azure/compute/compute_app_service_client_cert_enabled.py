import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.web import WebSiteManagementClient

def run_check(credential):
    """
    Checks if App Services have Client Certificates (Incoming client certificates) enabled.
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
                    client_cert_enabled = getattr(app, 'client_cert_enabled', False)
                    
                    if not client_cert_enabled:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-9.6", 
                            "check": "App Service Client Certificate Not Required",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "App Service",
                            "resource_type": "Microsoft.Web/sites",
                            "resource_id": app.id,
                            "region": app.location,
                            "description": f"App Service '{app.name}' does not require client certificates.",
                            "remediation": "Enable client certificates in the configuration to enforce mutual TLS (mTLS).",
                            "references": ["https://learn.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth"],
                            "resource_attributes": {
                                "app_name": app.name,
                                "client_cert_enabled": client_cert_enabled
                            },
                            "evidence": {
                                "client_cert_enabled": client_cert_enabled
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-9.6", 
                            "check": "App Service Client Certificate Not Required",
                            "severity": "High",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "App Service",
                            "resource_type": "Microsoft.Web/sites",
                            "resource_id": app.id,
                            "region": app.location,
                            "description": f"App Service '{app.name}' requires client certificates.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth"],
                            "resource_attributes": {
                                "app_name": app.name,
                                "client_cert_enabled": client_cert_enabled
                            },
                            "evidence": {
                                "client_cert_enabled": client_cert_enabled
                            }
                        })
            except Exception as e:
                pass 
                
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Service Client Cert check: {e}")

    return findings