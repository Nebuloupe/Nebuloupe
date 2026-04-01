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
            for db in sql_client.databases.list_by_server(server.resource_group_name, server.name):
                # master DB doesn't have TDE configured the same way
                if db.name.lower() == "master":
                    continue
                try:
                    tde = sql_client.transparent_data_encryptions.get(
                        server.resource_group_name,
                        server.name,
                        db.name,
                        "current"
                    )
                    if tde.state.lower() != "enabled":
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-4.1.1",
                            "check": "SQL Transparent Data Encryption (TDE) Not Enabled",
                            "severity": "High",
                            "status": "FAIL",
                            "cloud_provider": "azure",
                            "category": "SQL",
                            "resource_type": "Microsoft.Sql/servers/databases",
                            "resource_id": db.id,
                            "region": db.location,
                            "description": f"SQL Database '{db.name}' on server '{server.name}' does not have Transparent Data Encryption (TDE) enabled.",
                            "remediation": "Enable TDE on the SQL Database.",
                            "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview"],
                            "resource_attributes": {
                                "server_name": server.name,
                                "database_name": db.name,
                                "tde_state": tde.state
                            },
                            "evidence": {
                                "tde_state": tde.state
                            }
                        })
                    else:
                        findings.append({
                            "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                            "rule_id": "CIS-AZURE-4.1.1",
                            "check": "SQL Transparent Data Encryption (TDE) Not Enabled",
                            "severity": "High",
                            "status": "PASS",
                            "cloud_provider": "azure",
                            "category": "SQL",
                            "resource_type": "Microsoft.Sql/servers/databases",
                            "resource_id": db.id,
                            "region": db.location,
                            "description": f"SQL Database '{db.name}' on server '{server.name}' has Transparent Data Encryption (TDE) enabled.",
                            "remediation": "No action required.",
                            "references": ["https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview"],
                            "resource_attributes": {
                                "server_name": server.name,
                                "database_name": db.name,
                                "tde_state": tde.state
                            },
                            "evidence": {
                                "tde_state": tde.state
                            }
                        })
                except Exception as e:
                    pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for SQL TDE check: {e}")
    return findings
