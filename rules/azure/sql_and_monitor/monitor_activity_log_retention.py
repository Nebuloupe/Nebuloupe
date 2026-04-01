import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.monitor import MonitorManagementClient

def run_check(credential):
    findings = []
    try:
        sub_client = SubscriptionClient(credential)
        sub_id = list(sub_client.subscriptions.list())[0].subscription_id
        monitor_client = MonitorManagementClient(credential, sub_id)
        
        try:
            log_profiles = list(monitor_client.log_profiles.list())
            for profile in log_profiles:
                retention = getattr(profile, "retention_policy", None)
                days = getattr(retention, "days", 0)
                enabled = getattr(retention, "enabled", False)
                
                # Recommended retention is at least 365 days or 0 (infinite)
                if not enabled or (days < 365 and days != 0):
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-5.1",
                        "check": "Activity Log Retention Is Less Than 365 Days",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Monitor",
                        "resource_type": "Microsoft.Insights/logprofiles",
                        "resource_id": profile.id,
                        "region": profile.location,
                        "description": f"Log profile '{profile.name}' has activity log retention of {days} days. (Should be 365+ or 0)",
                        "remediation": "Update the log profile retention policy to 365 days or 0 for infinite.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"],
                        "resource_attributes": {
                            "profile_name": profile.name,
                            "retention_days": days,
                            "retention_enabled": enabled
                        },
                        "evidence": {
                            "retention_days": days,
                            "retention_enabled": enabled
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-5.1",
                        "check": "Activity Log Retention Is Less Than 365 Days",
                        "severity": "Medium",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "Monitor",
                        "resource_type": "Microsoft.Insights/logprofiles",
                        "resource_id": profile.id,
                        "region": profile.location,
                        "description": f"Log profile '{profile.name}' has activity log retention of {days} days. (Should be 365+ or 0)",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"],
                        "resource_attributes": {
                            "profile_name": profile.name,
                            "retention_days": days,
                            "retention_enabled": enabled
                        },
                        "evidence": {
                            "retention_days": days,
                            "retention_enabled": enabled
                        }
                    })
        except Exception as e:
            pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Activity Log Retention check: {e}")
    return findings
