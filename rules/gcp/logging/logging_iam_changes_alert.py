import uuid

# Keywords that identify an IAM changes metric filter
IAM_KEYWORDS = ['SetIamPolicy', 'google.iam.v1', 'iam_policy', 'v1.setIamPolicy']

def run_check(project_id: str):
    from googleapiclient import discovery

    logging_svc = discovery.build('logging', 'v2', cache_discovery=False)
    monitoring = discovery.build('monitoring', 'v3', cache_discovery=False)
    findings = []

    # Step 1: look for a log-based metric covering IAM policy changes
    metrics_resp = logging_svc.projects().metrics().list(
        parent=f"projects/{project_id}"
    ).execute()

    metrics = metrics_resp.get('metrics', [])
    iam_metric = None
    for m in metrics:
        filt = m.get('filter', '')
        if any(kw in filt for kw in IAM_KEYWORDS):
            iam_metric = m
            break

    metric_exists = iam_metric is not None

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
                if iam_metric['name'].split('/')[-1] in filter_str:
                    alert_exists = True
                    break

    fully_configured = metric_exists and alert_exists

    findings.append(create_finding(
        "GCP-LOG-07",
        "IAM Policy Changes Alert Configured",
        "High" if not fully_configured else "Low",
        "FAIL" if not fully_configured else "PASS",
        f"projects/{project_id}",
        "No log-based metric and alert configured for IAM policy changes." if not fully_configured
        else "Log-based metric and alert for IAM policy changes are configured.",
        "Create a log-based metric for SetIamPolicy events and attach a Cloud Monitoring alerting policy." if not fully_configured
        else "No action required.",
        {
            "metric_exists": metric_exists,
            "alert_exists": alert_exists,
            "metric_name": iam_metric['name'] if iam_metric else None
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
