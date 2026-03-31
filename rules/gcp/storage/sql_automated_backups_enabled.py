import uuid
from googleapiclient.discovery import build


def run_check(project_id: str):
    findings = []

    try:
        service = build("sqladmin", "v1beta4")
        instances_list = service.instances().list(project=project_id).execute()
        instances = instances_list.get("items", [])
    except Exception as e:
        return [create_finding(
            "GCP-SQL-03", "Cloud SQL Automated Backups Enabled", "High", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing Cloud SQL instances: {e}",
            "Ensure sqladmin.googleapis.com is enabled and caller has cloudsql.instances.list permission.",
            {"error": str(e)}
        )]

    if not instances:
        return [create_finding(
            "GCP-SQL-03", "Cloud SQL Automated Backups Enabled", "Low", "PASS",
            project_id, f"projects/{project_id}",
            "No Cloud SQL instances found in this project.",
            "No action required.",
            {"instance_count": 0}
        )]

    for instance in instances:
        instance_name = instance.get("name")
        settings = instance.get("settings", {})
        backup_config = settings.get("backupConfiguration", {})

        backup_enabled = backup_config.get("enabled", False)
        point_in_time = backup_config.get("pointInTimeRecoveryEnabled", False)
        backup_start_time = backup_config.get("startTime")
        retained_backups = (
            backup_config.get("backupRetentionSettings", {}).get("retainedBackups")
        )

        status = "PASS" if backup_enabled else "FAIL"
        desc = (
            f"Cloud SQL instance '{instance_name}' has automated backups enabled "
            f"(start time: {backup_start_time}, retained: {retained_backups}, "
            f"PITR: {point_in_time})."
            if backup_enabled
            else f"Cloud SQL instance '{instance_name}' does not have automated backups enabled. "
                 "Data loss may occur in the event of an incident."
        )

        findings.append(create_finding(
            "GCP-SQL-03", "Cloud SQL Automated Backups Enabled",
            "Low" if backup_enabled else "High",
            status, project_id, instance_name, desc,
            "Enable automated backups on all Cloud SQL instances. Configure a backup window, "
            "set a sufficient retention period, and enable point-in-time recovery (PITR) "
            "for MySQL and PostgreSQL instances.",
            {
                "backup_enabled": backup_enabled,
                "point_in_time_recovery_enabled": point_in_time,
                "backup_start_time": backup_start_time,
                "retained_backups": retained_backups,
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
            "https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
            "https://cloud.google.com/sql/docs/postgres/backup-recovery/pitr"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
