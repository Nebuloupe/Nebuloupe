import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.sql import SqlManagementClient

def run_check(credential):
    findings = []
    try:
        sub_client = SubscriptionClient(credential)
        sub_id = list(sub_client.subscriptions.list())[0].subscription_id
        sql_client = SqlManagementClient(credential, sub_id)
        
        for server in sql_client.servers.list():
            try:
                for rule in sql_client.firewall_rules.list_by_server(server.resource_group_name, server.name):
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "0.0.0.0":
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-4.1.3",
                            "check": "SQL Server Allows Public Azure Access",
                            "severity": "Medium",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "SQL",
                            "resource_type": "Microsoft.Sql/servers",
                            "resource_id": server.id,
                            "region": server.location,
                            "description": f"SQL Server '{server.name}' allows access to Azure services (0.0.0.0-0.0.0.0 firewall rule).",
                            "remediation": "Remove the 'Allow access to Azure services' firewall rule.",
                            "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"],
                            "resource_attributes": {
                                "server_name": server.name,
                                "firewall_rule_name": rule.name
                            },
                            "evidence": {
                                "start_ip": rule.start_ip_address,
                                "end_ip": rule.end_ip_address
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-4.1.3",
                            "check": "SQL Server Allows Public Azure Access",
                            "severity": "Medium",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "SQL",
                            "resource_type": "Microsoft.Sql/servers",
                            "resource_id": server.id,
                            "region": server.location,
                            "description": f"SQL Server '{server.name}' does not allow access to Azure services (0.0.0.0-0.0.0.0 firewall rule).",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure"],
                            "resource_attributes": {
                                "server_name": server.name,
                                "firewall_rule_name": rule.name
                            },
                            "evidence": {
                                "start_ip": rule.start_ip_address,
                                "end_ip": rule.end_ip_address
                            }
                        })
            except Exception as e:
                pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for SQL Firewall check: {e}")
    return findings
