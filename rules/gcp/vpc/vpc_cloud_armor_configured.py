import uuid

def run_check(project_id: str):
    from googleapiclient import discovery

    compute = discovery.build('compute', 'v1', cache_discovery=False)
    findings = []

    # Check backend services (global) for attached Cloud Armor security policies
    backend_services_resp = compute.backendServices().list(project=project_id).execute()
    backend_services = backend_services_resp.get('items', [])

    if not backend_services:
        findings.append(create_finding(
            "GCP-VPC-09",
            "Cloud Armor Configured on Backend Services",
            "Low",
            "PASS",
            f"projects/{project_id}",
            "No backend services found; Cloud Armor check not applicable.",
            "No action required.",
            {"backend_services_count": 0}
        ))
        return findings

    for bs in backend_services:
        security_policy = bs.get('securityPolicy', None)
        armor_configured = security_policy is not None
        policy_name = security_policy.split('/')[-1] if armor_configured else None

        findings.append(create_finding(
            "GCP-VPC-09",
            "Cloud Armor Configured on Backend Services",
            "High" if not armor_configured else "Low",
            "FAIL" if not armor_configured else "PASS",
            project_id,
            bs['selfLink'],
            f"Backend service '{bs['name']}' does not have a Cloud Armor security policy attached." if not armor_configured
            else f"Backend service '{bs['name']}' is protected by Cloud Armor policy '{policy_name}'.",
            "Attach a Cloud Armor security policy to this backend service to protect against DDoS and web attacks." if not armor_configured
            else "No action required.",
            {"backend_service": bs['name'], "security_policy": policy_name}
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
        "category": "Networking",
        "resource_type": "gcp_compute_backend_service",
        "resource_id": res_id,
        "region": "global",
        "description": desc,
        "remediation": rem,
        "references": [
            "https://cloud.google.com/armor/docs/cloud-armor-overview"
        ],
        "resource_attributes": {},
        "evidence": evidence
    }
