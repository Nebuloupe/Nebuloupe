import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    crm = discovery.build('cloudresourcemanager', 'v1')
    findings = []

    policy = crm.projects().getIamPolicy(
        resource=project_id, body={}
    ).execute()

    audit_configs = policy.get('auditConfigs', [])

    # Look for a project-wide audit config covering allServices
    all_services_config = next(
        (ac for ac in audit_configs if ac.get('service') == 'allServices'), None
    )

    log_types_enabled = set()
    if all_services_config:
        for log_config in all_services_config.get('auditLogConfigs', []):
            log_types_enabled.add(log_config.get('logType'))

    required_types = {'DATA_READ', 'DATA_WRITE', 'ADMIN_READ'}
    missing_types = required_types - log_types_enabled
    audit_complete = len(missing_types) == 0

    findings.append(create_finding(
        "GCP-LOG-01",
        "Audit Logs Enabled for All Services",
        "High" if not audit_complete else "Low",
        "FAIL" if not audit_complete else "PASS",
        f"projects/{project_id}",
        f"Project is missing audit log types: {', '.join(missing_types)}." if not audit_complete
        else "All audit log types (DATA_READ, DATA_WRITE, ADMIN_READ) are enabled for allServices.",
        "Enable DATA_READ, DATA_WRITE, and ADMIN_READ audit logs for allServices in the IAM policy." if not audit_complete
        else "No action required.",
        {
            "log_types_enabled": list(log_types_enabled),
            "missing_log_types": list(missing_types),
            "all_services_config_present": all_services_config is not None
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
        "project_id": project_id,
        "cloud_provider": "gcp",
        "category": "Logging",
        "resource_type": "gcp_project_iam_policy",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/logging/docs/audit"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
