import uuid

# Keywords that identify a VPC network changes metric filter
VPC_KEYWORDS = ['compute.networks', 'SetCommonInstanceMetadata', 'compute.firewalls',
                'compute.routes', 'v1.compute.networks']

def run_check(project_id: str):
    from googleapiclient import discovery

    logging_svc = discovery.build('logging', 'v2')
    monitoring = discovery.build('monitoring', 'v3')
    findings = []

    # Step 1: look for a log-based metric covering VPC network changes
    metrics_resp = logging_svc.projects().metrics().list(
        parent=f"projects/{project_id}"
    ).execute()

    metrics = metrics_resp.get('metrics', [])
    vpc_metric = None
    for m in metrics:
        filt = m.get('filter', '')
        if any(kw in filt for kw in VPC_KEYWORDS):
            vpc_metric = m
            break

    metric_exists = vpc_metric is not None

    # Step 2: check for an alerting policy referencing that metric
    alert_exists = False
    if metric_exists:
        alerts_resp = monitoring.projects().alertPolicies().list(
            name=f"projects/{project_id}"
        ).execute()
        for policy in alerts_resp.get('alertPolicies', []):
            for condition in policy.get('conditions', []):
                filter_str = condition.get('conditionThreshold', {}).get('filter', '') or \
                             condition.get('conditionAbsent', {}).get('filter', '')
                if vpc_metric['name'].split('/')[-1] in filter_str:
                    alert_exists = True
                    break

    fully_configured = metric_exists and alert_exists

    findings.append(create_finding(
        "GCP-LOG-06",
        "VPC Network Changes Alert Configured",
        "Medium" if not fully_configured else "Low",
        "FAIL" if not fully_configured else "PASS",
        f"projects/{project_id}",
        "No log-based metric and alert found for VPC network configuration changes." if not fully_configured
        else "Log-based metric and alert for VPC network changes are configured.",
        "Create a log-based metric targeting VPC network/firewall/route changes and add a Cloud Monitoring alert." if not fully_configured
        else "No action required.",
        {
            "metric_exists": metric_exists,
            "alert_exists": alert_exists,
            "metric_name": vpc_metric['name'] if vpc_metric else None
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
