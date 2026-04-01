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
                # Should capture all regions and global
                all_regions_captured = True if "global" in profile.locations else False
                
                # Verify standard categories are configured
                categories_set = set(cat.lower() for cat in profile.categories)
                required = {"write", "delete", "action"}
                
                if not required.issubset(categories_set) or not all_regions_captured:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-5.2",
                        "check": "Log Profile Not Capturing All Regions and Action Types",
                        "severity": "Medium",
                        "status": "FAIL",
                        "cloud_provider": "azure",
                        "category": "Monitor",
                        "resource_type": "Microsoft.Insights/logprofiles",
                        "resource_id": profile.id,
                        "region": profile.location,
                        "description": f"Log profile '{profile.name}' is missing 'global' location or mandatory categories (Write/Delete/Action).",
                        "remediation": "Update the log profile to include 'global' and all region locations, plus 'Write', 'Delete', 'Action' categories.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"],
                        "resource_attributes": {
                            "profile_name": profile.name,
                            "categories": profile.categories,
                            "locations": profile.locations
                        },
                        "evidence": {
                            "categories": profile.categories,
                            "locations": profile.locations
                        }
                    })
                else:
                    findings.append({
                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                        "rule_id": "CIS-AZURE-5.2",
                        "check": "Log Profile Not Capturing All Regions and Action Types",
                        "severity": "Medium",
                        "status": "PASS",
                        "cloud_provider": "azure",
                        "category": "Monitor",
                        "resource_type": "Microsoft.Insights/logprofiles",
                        "resource_id": profile.id,
                        "region": profile.location,
                        "description": f"Log profile '{profile.name}' is capturing 'global' location and mandatory categories (Write/Delete/Action).",
                        "remediation": "No action required.",
                        "references": ["https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log"],
                        "resource_attributes": {
                            "profile_name": profile.name,
                            "categories": profile.categories,
                            "locations": profile.locations
                        },
                        "evidence": {
                            "categories": profile.categories,
                            "locations": profile.locations
                        }
                    })
        except Exception as e:
            pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Log Profile setup check: {e}")
    return findings
