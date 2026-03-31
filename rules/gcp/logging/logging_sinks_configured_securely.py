import uuid

def run_check(credentials, project_id):
    from googleapiclient import discovery

    logging_svc = discovery.build('logging', 'v2', credentials=credentials)
    findings = []

    sinks_resp = logging_svc.projects().sinks().list(
        parent=f"projects/{project_id}"
    ).execute()

    sinks = sinks_resp.get('sinks', [])

    if not sinks:
        findings.append(create_finding(
            "GCP-LOG-02",
            "Log Sinks Configured Securely",
            "Medium",
            "FAIL",
            f"projects/{project_id}",
            "No log sinks found. Logs are not being exported to a secure destination.",
            "Create at least one log sink exporting to a secure Cloud Storage bucket, BigQuery dataset, or Pub/Sub topic.",
            {"sink_count": 0}
        ))
        return findings

    for sink in sinks:
        sink_name = sink['name'].split('/')[-1]
        destination = sink.get('destination', '')
        disabled = sink.get('disabled', False)
        writer_identity = sink.get('writerIdentity', '')

        # Flag sinks that are disabled or have no destination
        insecure = disabled or not destination

        findings.append(create_finding(
            "GCP-LOG-02",
            "Log Sinks Configured Securely",
            "Medium" if insecure else "Low",
            "FAIL" if insecure else "PASS",
            f"projects/{project_id}/sinks/{sink_name}",
            f"Log sink '{sink_name}' is disabled or has no destination." if insecure
            else f"Log sink '{sink_name}' is active and exporting to '{destination}'.",
            "Enable the log sink and ensure its destination is a secured, access-controlled resource." if insecure
            else "No action required.",
            {
                "sink_name": sink_name,
                "destination": destination,
                "disabled": disabled,
                "writer_identity": writer_identity
            }
        ))

    return findings


def create_finding(rule_id, check, severity, status, res_id, desc, rem, evidence):
    return {
        "finding_id": str(uuid.uuid4()),
        "rule_id": rule_id,
        "check": check,
        "severity": severity,
        "status": status,
        "cloud_provider": "gcp",
        "category": "Logging",
        "resource_type": "gcp_logging_sink",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/logging/docs/export/configure_export_v2"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
