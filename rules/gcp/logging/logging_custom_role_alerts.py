import uuid

# Log filter that matches custom role create/update/delete events
CUSTOM_ROLE_FILTER = (
    'resource.type="iam_role" AND '
    'protoPayload.methodName=('
    '"google.iam.admin.v1.CreateRole" OR '
    '"google.iam.admin.v1.UpdateRole" OR '
    '"google.iam.admin.v1.DeleteRole")'
)

def run_check(project_id: str):
    from googleapiclient import discovery

    logging_svc = discovery.build('logging', 'v2', cache_discovery=False)
    monitoring = discovery.build('monitoring', 'v3', cache_discovery=False)
    findings = []

    # Step 1: check for a log-based metric covering custom role changes
    metrics_resp = logging_svc.projects().metrics().list(
        parent=f"projects/{project_id}"
    ).execute()

    metrics = metrics_resp.get('metrics', [])
    role_metric = None
    for m in metrics:
        filt = m.get('filter', '')
        if 'CreateRole' in filt or 'UpdateRole' in filt or 'DeleteRole' in filt or 'iam_role' in filt:
            role_metric = m
            break

    metric_exists = role_metric is not None

    # Step 2: check for an alerting policy tied to that metric
    alert_exists = False
    if metric_exists:
        alerts_resp = monitoring.projects().alertPolicies().list(
            name=f"projects/{project_id}"
        ).execute()
        for policy in alerts_resp.get('alertPolicies', []):
            for condition in policy.get('conditions', []):
                filter_str = condition.get('conditionThreshold', {}).get('filter', '') or \
                             condition.get('conditionAbsent', {}).get('filter', '')
                if role_metric['name'].split('/')[-1] in filter_str or 'iam_role' in filter_str:
                    alert_exists = True
                    break

    fully_configured = metric_exists and alert_exists

    findings.append(create_finding(
        "GCP-LOG-05",
        "Custom Role Changes Alert Configured",
        "Medium" if not fully_configured else "Low",
        "FAIL" if not fully_configured else "PASS",
        f"projects/{project_id}",
        "No log-based metric and alerting policy found for custom IAM role changes." if not fully_configured
        else "Log-based metric and alert for custom role changes are configured.",
        "Create a log-based metric for custom role mutations and attach a Cloud Monitoring alert policy." if not fully_configured
        else "No action required.",
        {
            "metric_exists": metric_exists,
            "alert_exists": alert_exists,
            "metric_name": role_metric['name'] if role_metric else None
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
        "resource_type": "gcp_logging_metric",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/logging/docs/logs-based-metrics",
            "https://cloud.google.com/monitoring/alerts"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
