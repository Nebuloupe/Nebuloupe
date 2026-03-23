import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.security import SecurityCenter

def run_check(credential):
    findings = []
    try:
        sub_client = SubscriptionClient(credential)
        sub_id = list(sub_client.subscriptions.list())[0].subscription_id
        security_client = SecurityCenter(credential, sub_id)
        
        try:
            pricings = security_client.pricings.list()
            defender_on = False
            for pricing in pricings:
                # Typically pricing name 'SqlServers' or 'SqlServerVirtualMachines'
                if pricing.name == "SqlServers" and pricing.pricing_tier.lower() == "standard":
                    defender_on = True
                    break

            if not defender_on:
                findings.append({
                    "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                    "rule_id": "CIS-AZURE-2.2",
                    "check": "Defender for SQL Not Enabled",
                    "severity": "Medium",
                    "status": "FAIL",
                    "cloud_provider": "azure",
                    "category": "Monitor",
                    "resource_type": "Microsoft.Security/pricings",
                    "resource_id": f"/subscriptions/{sub_id}/providers/Microsoft.Security/pricings/SqlServers",
                    "region": "global",
                    "description": f"Subscription '{sub_id}' does not have Microsoft Defender for SQL enabled.",
                    "remediation": "Enable Microsoft Defender for SQL in Microsoft Defender for Cloud.",
                    "references": ["https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-sql-introduction"],
                    "resource_attributes": {
                        "subscription_id": sub_id,
                        "defender_for_sql": "Free/Off"
                    },
                    "evidence": {
                        "defender_for_sql": "Free/Off"
                    }
                })
        except Exception as e:
            pass
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for Defender for SQL check: {e}")
    return findings
