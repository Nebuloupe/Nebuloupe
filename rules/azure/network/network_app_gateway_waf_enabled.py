import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Application Gateways have Web Application Firewall (WAF) enabled in Prevention mode.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            for appgw in network_client.application_gateways.list_all():
                try:
                    waf_config = getattr(appgw, "web_application_firewall_configuration", None)
                    waf_enabled = False
                    waf_mode = "None"
                    
                    if waf_config:
                        waf_enabled = getattr(waf_config, 'enabled', False)
                        waf_mode = getattr(waf_config, 'firewall_mode', "None")
                        
                    if not waf_enabled or str(waf_mode).lower() != "prevention":
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-6.X", # Custom / WAF Rule
                            "check": "Application Gateway WAF is not Enabled in Prevention Mode",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "Network",
                            "resource_type": "Microsoft.Network/applicationGateways",
                            "resource_id": appgw.id,
                            "region": appgw.location,
                            "description": f"Application Gateway '{appgw.name}' does not have WAF enabled in 'Prevention' mode (Current mode: {waf_mode}).",
                            "remediation": "Enable the Web Application Firewall (WAF) on the Application Gateway and set its mode to 'Prevention'.",
                            "references": ["https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview"],
                            "resource_attributes": {
                                "waf_enabled": waf_enabled,
                                "waf_mode": str(waf_mode)
                            },
                            "evidence": {
                                "app_gateway_name": appgw.name,
                                "sku_name": str(appgw.sku.name) if getattr(appgw, 'sku', None) else "Unknown"
                            }
                        })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze WAF for App Gateway {appgw.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for App Gateway WAF check: {e}")

    return findings