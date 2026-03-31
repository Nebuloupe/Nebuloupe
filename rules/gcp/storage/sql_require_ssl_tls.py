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
            "GCP-SQL-02", "Cloud SQL Require SSL/TLS", "High", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing Cloud SQL instances: {e}",
            "Ensure sqladmin.googleapis.com is enabled and caller has cloudsql.instances.list permission.",
            {"error": str(e)}
        )]

    if not instances:
        return [create_finding(
            "GCP-SQL-02", "Cloud SQL Require SSL/TLS", "Low", "PASS",
            project_id, f"projects/{project_id}",
            "No Cloud SQL instances found in this project.",
            "No action required.",
            {"instance_count": 0}
        )]

    for instance in instances:
        instance_name = instance.get("name")
        settings = instance.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})

        # requireSsl is the legacy flag; sslMode supersedes it in newer API versions
        require_ssl = ip_config.get("requireSsl", False)
        ssl_mode = ip_config.get("sslMode", "")  # ALLOW_UNENCRYPTED_AND_ENCRYPTED | ENCRYPTED_ONLY | TRUSTED_CLIENT_CERTIFICATE_REQUIRED

        # ENCRYPTED_ONLY or TRUSTED_CLIENT_CERTIFICATE_REQUIRED = compliant
        ssl_enforced = (
            ssl_mode in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")
            or require_ssl is True
        )

        status = "PASS" if ssl_enforced else "FAIL"
        desc = (
            f"Cloud SQL instance '{instance_name}' enforces SSL/TLS connections "
            f"(sslMode='{ssl_mode}', requireSsl={require_ssl})."
            if ssl_enforced
            else f"Cloud SQL instance '{instance_name}' allows unencrypted connections "
                 f"(sslMode='{ssl_mode}', requireSsl={require_ssl})."
        )

        findings.append(create_finding(
            "GCP-SQL-02", "Cloud SQL Require SSL/TLS",
            "Low" if ssl_enforced else "High",
            status, project_id, instance_name, desc,
            "Set 'sslMode' to 'ENCRYPTED_ONLY' or 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED' "
            "on the Cloud SQL instance to enforce encrypted connections. "
            "Update all client connection strings to include SSL certificates.",
            {
                "ssl_mode": ssl_mode or None,
                "require_ssl_legacy": require_ssl,
                "ssl_enforced": ssl_enforced,
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
            "https://cloud.google.com/sql/docs/mysql/configure-ssl-instance",
            "https://cloud.google.com/sql/docs/postgres/configure-ssl-instance"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
