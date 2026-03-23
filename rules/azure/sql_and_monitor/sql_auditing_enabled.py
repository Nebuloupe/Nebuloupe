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
                auditing = sql_client.server_blob_auditing_policies.get(
                    server.resource_group_name,
                    server.name,
                )
                if auditing.state.lower() != "enabled":
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-4.1.2",
                        "check": "SQL Server Auditing Not Enabled",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "SQL",
                        "resource_type": "Microsoft.Sql/servers",
                        "resource_id": server.id,
                        "region": server.location,
                        "description": f"SQL Server '{server.name}' does not have auditing enabled.",
                        "remediation": "Enable Auditing on the SQL Server.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview"],
                        "resource_attributes": {
                            "server_name": server.name,
                            "auditing_state": auditing.state
                        },
                        "evidence": {
                            "auditing_state": auditing.state
                        }
                    })
            except Exception as e:
                pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for SQL Auditing check: {e}")
    return findings
