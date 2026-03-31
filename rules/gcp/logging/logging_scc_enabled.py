import uuid

def run_check(project_id: str):
    from googleapiclient import discovery
    from googleapiclient.errors import HttpError

    findings = []

    try:
        scc = discovery.build('securitycenter', 'v1')

        # List sources for the project — a successful call confirms SCC is accessible/enabled
        sources_resp = scc.projects().sources().list(
            parent=f"projects/{project_id}"
        ).execute()

        sources = sources_resp.get('sources', [])
        scc_enabled = True
        source_count = len(sources)

    except HttpError as e:
        if e.resp.status in (403, 404):
            scc_enabled = False
            source_count = 0
        else:
            raise e

    findings.append(create_finding(
        "GCP-LOG-03",
        "Security Command Center Enabled",
        "High" if not scc_enabled else "Low",
        "FAIL" if not scc_enabled else "PASS",
        f"projects/{project_id}",
        "Security Command Center (SCC) is not enabled for this project." if not scc_enabled
        else f"Security Command Center is enabled with {source_count} source(s) configured.",
        "Enable Security Command Center Standard or Premium tier for threat detection and security findings." if not scc_enabled
        else "No action required.",
        {"scc_enabled": scc_enabled, "source_count": source_count}
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
        "resource_type": "gcp_scc_project",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/security-command-center/docs/overview"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
