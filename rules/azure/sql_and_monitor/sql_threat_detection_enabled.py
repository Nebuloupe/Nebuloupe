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
                td_policy_list = list(sql_client.server_security_alert_policies.list_by_server(server.resource_group_name, server.name))
                td_enabled = False
                for td_policy in td_policy_list:
                    if td_policy.state.lower() == "enabled":
                        td_enabled = True
                        break

                if not td_enabled:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-4.1.5",
                        "check": "SQL Server Threat Detection Not Enabled",
                        "severity": "High",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "SQL",
                        "resource_type": "Microsoft.Sql/servers",
                        "resource_id": server.id,
                        "region": server.location,
                        "description": f"SQL Server '{server.name}' does not have Threat Detection (Advanced Data Security) enabled.",
                        "remediation": "Enable Threat Detection on the SQL server.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview"],
                        "resource_attributes": {
                            "server_name": server.name,
                            "td_enabled": False
                        },
                        "evidence": {
                            "td_enabled": False
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-4.1.5",
                        "check": "SQL Server Threat Detection Not Enabled",
                        "severity": "High",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "SQL",
                        "resource_type": "Microsoft.Sql/servers",
                        "resource_id": server.id,
                        "region": server.location,
                        "description": f"SQL Server '{server.name}' has Threat Detection (Advanced Data Security) enabled.",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-overview"],
                        "resource_attributes": {
                            "server_name": server.name,
                            "td_enabled": True
                        },
                        "evidence": {
                            "td_enabled": True
                        }
                    })
            except Exception as e:
                pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for SQL Threat Detection check: {e}")
    return findings
