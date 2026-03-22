import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def run_check(credential):
    """
    Checks if Network Security Groups (NSGs) allow inbound SQL (1433, 3306, 5432) from the internet.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())
        
        target_ports = [1433, 3306, 5432]

        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)

            for nsg in network_client.network_security_groups.list_all():
                try:
                    for rule in nsg.security_rules:
                        if rule.direction == "Inbound" and rule.access == "Allow":
                            src_prefix = str(rule.source_address_prefix).lower()
                            src_prefixes = [p.lower() for p in (rule.source_address_prefixes or [])]
                            
                            is_public = False
                            if src_prefix in ["*", "0.0.0.0", "0.0.0.0/0", "internet", "any"]:
                                is_public = True
                            for p in src_prefixes:
                                if p in ["*", "0.0.0.0", "0.0.0.0/0", "internet", "any"]:
                                    is_public = True
                                    
                            if is_public:
                                db_ports_open = []
                                dest_ports = []
                                if rule.destination_port_range:
                                    dest_ports.append(str(rule.destination_port_range))
                                if rule.destination_port_ranges:
                                    dest_ports.extend([str(p) for p in rule.destination_port_ranges])
                                    
                                for p in dest_ports:
                                    if p == "*":
                                        db_ports_open.extend(target_ports)
                                    elif "-" in p:
                                        try:
                                            start_port, end_port = map(int, p.split("-"))
                                            for tp in target_ports:
                                                if start_port <= tp <= end_port:
                                                    db_ports_open.append(tp)
                                        except ValueError:
                                            pass
                                    else:
                                        try:
                                            port_num = int(p)
                                            if port_num in target_ports:
                                                db_ports_open.append(port_num)
                                        except ValueError:
                                            pass
                                            
                                if db_ports_open:
                                    findings.append({
                                        "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                        "rule_id": "CIS-AZURE-6.1",
                                        "check": "NSG Inbound SQL Open to Internet",
                                        "severity": "High",
                                        "status": "FAIL",
                                        "cloud_provider": "azure",
                                        "category": "Network",
                                        "resource_type": "Microsoft.Network/networkSecurityGroups",
                                        "resource_id": nsg.id,
                                        "region": nsg.location,
                                        "description": f"NSG '{nsg.name}' allows inbound SQL database access (ports {set(db_ports_open)}) from the internet.",
                                        "remediation": f"Block inbound internet access to SQL ports {target_ports} in NSG '{nsg.name}'.",
                                        "references": ["https://learn.microsoft.com/en-us/azure/security/fundamentals/network-best-practices"],
                                        "resource_attributes": {
                                            "nsg_name": nsg.name,
                                            "rule_name": rule.name,
                                            "exposed_ports": list(set(db_ports_open))
                                        },
                                        "evidence": {
                                            "rule_details": f"Rule {rule.name} allows Source: {src_prefix} to Ports: {dest_ports}"
                                        }
                                    })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze NSG rules for {nsg.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for NSG SQL check: {e}")

    return findings