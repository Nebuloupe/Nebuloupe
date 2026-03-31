import uuid
from googleapiclient.discovery import build


# This check applies only to SQL Server instances
SQLSERVER_PREFIX = "SQLSERVER"
TARGET_FLAG = "contained database authentication"
SAFE_VALUE = "off"


def run_check(project_id: str):
    """
    Checks that the 'contained database authentication' flag is set to 'off'
    on all Cloud SQL SQL Server instances.

    Contained database authentication allows users to authenticate directly
    to a contained database without a login at the server level, bypassing
    server-level security policies. Disabling this reduces the attack surface.
    """
    findings = []

    try:
        service = build("sqladmin", "v1beta4")
        instances_list = service.instances().list(project=project_id).execute()
        instances = instances_list.get("items", [])
    except Exception as e:
        return [create_finding(
            "GCP-SQL-05", "Cloud SQL Contained DB Authentication Disabled", "High", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing Cloud SQL instances: {e}",
            "Ensure sqladmin.googleapis.com is enabled and caller has cloudsql.instances.list permission.",
            {"error": str(e)}
        )]

    sql_server_instances = [
        i for i in instances
        if i.get("databaseVersion", "").startswith(SQLSERVER_PREFIX)
    ]

    if not sql_server_instances:
        return [create_finding(
            "GCP-SQL-05", "Cloud SQL Contained DB Authentication Disabled", "Low", "PASS",
            project_id, f"projects/{project_id}",
            "No SQL Server Cloud SQL instances found — check is not applicable.",
            "No action required.",
            {"sql_server_instance_count": 0}
        )]

    for instance in sql_server_instances:
        instance_name = instance.get("name")
        settings = instance.get("settings", {})
        db_flags = settings.get("databaseFlags", [])

        flag_map = {f["name"].lower(): f["value"].lower() for f in db_flags}
        flag_value = flag_map.get(TARGET_FLAG)

        # Default in SQL Server is off; absent flag = safe default but recommend explicit
        is_disabled = (flag_value is None) or (flag_value == SAFE_VALUE)

        status = "PASS" if is_disabled else "FAIL"
        desc = (
            f"SQL Server instance '{instance_name}': '{TARGET_FLAG}' is "
            + ("explicitly set to 'off'." if flag_value == SAFE_VALUE else
               "not explicitly configured (SQL Server defaults to off — recommend explicit setting)."
               if flag_value is None else
               f"set to '{flag_value}', enabling contained database authentication.")
        )

        findings.append(create_finding(
            "GCP-SQL-05", "Cloud SQL Contained DB Authentication Disabled",
            "Low" if is_disabled else "High",
            status, project_id, instance_name, desc,
            f"Set the database flag '{TARGET_FLAG}' to 'off' on all Cloud SQL SQL Server "
            "instances to prevent users from authenticating directly to contained databases, "
            "ensuring all authentication flows through server-level login policies.",
            {
                "flag": TARGET_FLAG,
                "flag_value": flag_value,
                "is_safe": is_disabled,
                "database_version": instance.get("databaseVersion"),
                "region": instance.get("region")
            }
        ))

    return findings


def create_finding(rule_id, check, severity, status, project_id, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Storage",
        "resource_type": "gcp_sql_instance",
        "resource_id": res_id,
        "project_id": project_id,
        "region": evidence.get("region", "global") if isinstance(evidence, dict) else "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/sql/docs/sqlserver/flags",
            "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
