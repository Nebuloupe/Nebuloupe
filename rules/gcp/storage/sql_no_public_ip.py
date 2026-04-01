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
            "GCP-SQL-01", "Cloud SQL No Public IP", "Critical", "ERROR",
            project_id, f"projects/{project_id}",
            f"Error listing Cloud SQL instances: {e}",
            "Ensure sqladmin.googleapis.com is enabled and caller has cloudsql.instances.list permission.",
            {"error": str(e)}
        )]

    if not instances:
        return [create_finding(
            "GCP-SQL-01", "Cloud SQL No Public IP", "Low", "PASS",
            project_id, f"projects/{project_id}",
            "No Cloud SQL instances found in this project.",
            "No action required.",
            {"instance_count": 0}
        )]

    for instance in instances:
        instance_name = instance.get("name")
        ip_addresses = instance.get("ipAddresses", [])
        settings = instance.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})

        # ipv4Enabled=True means a public IPv4 address is assigned
        public_ip_enabled = ip_config.get("ipv4Enabled", False)
        public_ips = [
            ip["ipAddress"] for ip in ip_addresses
            if ip.get("type") == "PRIMARY"
        ]

        # Check for authorized networks (open CIDR blocks are an aggravating factor)
        authorized_networks = ip_config.get("authorizedNetworks", [])
        open_networks = [
            n for n in authorized_networks
            if n.get("value") in ("0.0.0.0/0", "::/0")
        ]

        status = "FAIL" if public_ip_enabled else "PASS"
        severity = "Critical" if (public_ip_enabled and open_networks) else ("High" if public_ip_enabled else "Low")

        desc = (
            f"Cloud SQL instance '{instance_name}' has a public IP enabled"
            + (f" and is accessible from any address (0.0.0.0/0)." if open_networks else ".")
            if public_ip_enabled
            else f"Cloud SQL instance '{instance_name}' does not have a public IP."
        )

        findings.append(create_finding(
            "GCP-SQL-01", "Cloud SQL No Public IP",
            severity, status, project_id, instance_name, desc,
            "Disable the public IP on Cloud SQL instances and connect via Cloud SQL Auth Proxy, "
            "Private Service Connect, or a private IP within a VPC. Remove all authorized networks "
            "if a public IP cannot be removed immediately.",
            {
                "public_ip_enabled": public_ip_enabled,
                "public_ips": public_ips,
                "open_authorized_networks": open_networks,
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
            "https://cloud.google.com/sql/docs/mysql/configure-private-ip",
            "https://cloud.google.com/sql/docs/mysql/connect-auth-proxy"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
