import uuid
from azure.mgmt.subscription import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient

def is_port_exposed(ports_property, target_ports=(22, 3389)):
    """
    Checks if a port property (string or list) overlaps with the target ports.
    Handles '*', '22', '20-30', or lists of these.
    """
    if not ports_property:
        return False
    
    ports_list = ports_property if isinstance(ports_property, list) else [ports_property]
    
    for port_item in ports_list:
        if port_item == '*':
            return True
        try:
            if '-' in port_item:
                start_port, end_port = map(int, port_item.split('-'))
                for tp in target_ports:
                    if start_port <= tp <= end_port:
                        return True
            else:
                if int(port_item) in target_ports:
                    return True
        except ValueError:
            continue
    return False

def is_source_public(source_property):
    """
    Checks if the source address prefix indicates public access.
    """
    if not source_property:
        return False
    
    source_list = source_property if isinstance(source_property, list) else [source_property]
    public_indicators = ['*', '0.0.0.0', '0.0.0.0/0', 'Internet', '<nw>Internet</nw>']
    
    # Azure's raw API sometimes returns 'Internet' or '*'
    for p in source_list:
        if p.strip().lower() in [i.lower() for i in public_indicators]:
            return True
    return False

def run_check(credential):
    """
    Checks if Azure Network Security Groups have rules exposing Port 22 or 3389 to the world.
    """
    findings = []
    
    try:
        sub_client = SubscriptionClient(credential)
        subscriptions = list(sub_client.subscriptions.list())
        
        for sub in subscriptions:
            sub_id = sub.subscription_id
            network_client = NetworkManagementClient(credential, sub_id)
            
            # Use list_all to get NSGs across all resource groups
            for nsg in network_client.network_security_groups.list_all():
                try:
                    for rule in nsg.security_rules:
                        # We only care about Inbound and Allows
                        if rule.direction.lower() == 'inbound' and rule.access.lower() == 'allow':
                            
                            # Extract address prefixes (handling both single string and lists)
                            source_prefixes = rule.source_address_prefix if rule.source_address_prefix else rule.source_address_prefixes
                            
                            # Extract destination ports (handling both single string and lists)
                            dest_ports = rule.destination_port_range if rule.destination_port_range else rule.destination_port_ranges
                            
                            if is_source_public(source_prefixes) and is_port_exposed(dest_ports, [22, 3389]):
                                
                                findings.append({
                                    "finding_id": f"NL-AZ-{uuid.uuid4().hex[:6].upper()}",
                                    "rule_id": "CIS-AZURE-9.1",
                                    "check": "Port 22/3389 is Open to World",
                                    "severity": "High",
                                    "status": "FAIL",
                                    "cloud_provider": "azure",
                                    "category": "Network",
                                    "resource_type": "Microsoft.Network/networkSecurityGroups/securityRules",
                                    "resource_id": rule.id,
                                    "region": nsg.location,
                                    "description": f"NSG '{nsg.name}' allows inbound public access (0.0.0.0/0) to SSH/RDP ports via rule '{rule.name}'.",
                                    "remediation": "Restrict SSH/RDP access to known IP addresses, or use Azure Bastion.",
                                    "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
                                    "resource_attributes": {
                                        "nsg_name": nsg.name,
                                        "rule_name": rule.name,
                                        "priority": rule.priority
                                    },
                                    "evidence": {
                                        "source_address_prefix": source_prefixes,
                                        "destination_port_range": dest_ports,
                                        "access": rule.access
                                    }
                                })
                except Exception as e:
                    print(f"       [!] Warning: Could not analyze NSG {nsg.name}: {e}")
                    
    except Exception as e:
        print(f"   [!] Error querying Azure subscriptions for NSG open port check: {e}")

    return findings
