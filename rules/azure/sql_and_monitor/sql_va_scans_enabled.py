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
                va_enabled = False
                for assessment in sql_client.server_vulnerability_assessments.list_by_server(server.resource_group_name, server.name):
                    va_enabled = True
                    break

                if not va_enabled:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-4.1.4",
                        "check": "SQL Server Vulnerability Assessment Not Enabled",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "SQL",
                        "resource_type": "Microsoft.Sql/servers",
                        "resource_id": server.id,
                        "region": server.location,
                        "description": f"SQL Server '{server.name}' does not have Vulnerability Assessment (VA) enabled.",
                        "remediation": "Enable Vulnerability Assessment on the SQL server.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment"],
                        "resource_attributes": {
                            "server_name": server.name,
                            "va_enabled": False
                        },
                        "evidence": {
                            "va_enabled": False
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-4.1.4",
                        "check": "SQL Server Vulnerability Assessment Not Enabled",
                        "severity": "Medium",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "SQL",
                        "resource_type": "Microsoft.Sql/servers",
                        "resource_id": server.id,
                        "region": server.location,
                        "description": f"SQL Server '{server.name}' has Vulnerability Assessment (VA) enabled.",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-vulnerability-assessment"],
                        "resource_attributes": {
                            "server_name": server.name,
                            "va_enabled": True
                        },
                        "evidence": {
                            "va_enabled": True
                        }
                    })
            except Exception as e:
                pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for SQL VA check: {e}")
    return findings
