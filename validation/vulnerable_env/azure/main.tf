terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.15.0"
    }
  }
}

provider "azurerm" {
  features {}
  # Using local auth fallback if variables are empty
  client_id       = var.client_id != "" ? var.client_id : null
  client_secret   = var.client_secret != "" ? var.client_secret : null
  tenant_id       = var.tenant_id != "" ? var.tenant_id : null
  subscription_id = var.subscription_id != "" ? var.subscription_id : null
}

provider "azuread" {
  client_id     = var.client_id != "" ? var.client_id : null
  client_secret = var.client_secret != "" ? var.client_secret : null
  tenant_id     = var.tenant_id != "" ? var.tenant_id : null
}

data "azurerm_client_config" "current" {}

data "azuread_domains" "default" {
  only_initial = true
}

resource "random_id" "suffix" {
  byte_length = 4
}

# ----------------------------------------------------------------------------------
# Resource Group
# ----------------------------------------------------------------------------------
resource "azurerm_resource_group" "vuln_rg" {
  name     = "nebuloupe-vuln-env"
  location = "East US"
}

# ----------------------------------------------------------------------------------
# STORAGE RESOURCES (Missing TLS 1.2, Soft Delete, Private Endpoints, Encryption)
# ----------------------------------------------------------------------------------
resource "azurerm_storage_account" "vuln_storage" {
  name                     = "nebuloupevulnstg${random_id.suffix.hex}"
  resource_group_name      = azurerm_resource_group.vuln_rg.name
  location                 = azurerm_resource_group.vuln_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # VULNERABILITY: TLS < 1.2
  min_tls_version = "TLS1_0" 

  # VULNERABILITY: Infrastructure encryption disabled
  infrastructure_encryption_enabled = false

  # VULNERABILITY: Blob versioning is explicitly disabled via lack of block
  # VULNERABILITY: Trusted MS services bypass is omitted from network rules
  blob_properties {
    # VULNERABILITY: No soft delete policy
  }
}

# ----------------------------------------------------------------------------------
# NETWORK RESOURCES (Missing NSG Flow Logs, WAF, DDoS, Watcher, Bastion)
# ----------------------------------------------------------------------------------
resource "azurerm_virtual_network" "vuln_vnet" {
  name                = "vuln-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.vuln_rg.location
  resource_group_name = azurerm_resource_group.vuln_rg.name

  # VULNERABILITY: DDoS protection plan omitted
  # VULNERABILITY: Bastion subnet omitted
}

resource "azurerm_subnet" "vuln_subnet" {
  name                 = "vuln-subnet"
  resource_group_name  = azurerm_resource_group.vuln_rg.name
  virtual_network_name = azurerm_virtual_network.vuln_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
  
  # VULNERABILITY: Missing private link / endpoint policies
}

resource "azurerm_public_ip" "vuln_pip" {
  name                = "vuln-vm-pip"
  location            = azurerm_resource_group.vuln_rg.location
  resource_group_name = azurerm_resource_group.vuln_rg.name
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_security_group" "vuln_nsg" {
  name                = "vuln-nsg"
  location            = azurerm_resource_group.vuln_rg.location
  resource_group_name = azurerm_resource_group.vuln_rg.name

  # VULNERABILITY: Exposing SQL port 1433 to the internet
  security_rule {
    name                       = "Allow-SQL-Any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  
  # VULNERABILITY: NSG Flow Logs are explicitly omitted (requires azurerm_network_watcher_flow_log)
}

resource "azurerm_network_interface" "vuln_nic" {
  name                = "vuln-nic"
  location            = azurerm_resource_group.vuln_rg.location
  resource_group_name = azurerm_resource_group.vuln_rg.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.vuln_subnet.id
    private_ip_address_allocation = "Dynamic"
    # VULNERABILITY: VM has a direct Public IP attached
    public_ip_address_id          = azurerm_public_ip.vuln_pip.id
  }
}

# ----------------------------------------------------------------------------------
# COMPUTE RESOURCES (Missing Endpoint Protection, Auth, Vuln Scans, Auto updates)
# ----------------------------------------------------------------------------------
resource "azurerm_linux_virtual_machine" "vuln_vm" {
  name                            = "vuln-linux-vm"
  resource_group_name             = azurerm_resource_group.vuln_rg.name
  location                        = azurerm_resource_group.vuln_rg.location
  size                            = "Standard_B1s"
  admin_username                  = "adminuser"
  admin_password                  = "P@ssw0rd1234!!!" # Weak password
  network_interface_ids           = [azurerm_network_interface.vuln_nic.id]

  # VULNERABILITY: Password auth enabled
  disable_password_authentication = false

  # VULNERABILITY: Missing extensions (Endpoint protection, VA scanner)
  # VULNERABILITY: Automatic OS updates are handled manually

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    # VULNERABILITY: Disk encryption not configured
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}

# App Service (Web App)
resource "azurerm_service_plan" "vuln_asp" {
  name                = "vuln-asp"
  resource_group_name = azurerm_resource_group.vuln_rg.name
  location            = azurerm_resource_group.vuln_rg.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "vuln_webapp" {
  name                = "vuln-webapp-${random_id.suffix.hex}"
  resource_group_name = azurerm_resource_group.vuln_rg.name
  location            = azurerm_service_plan.vuln_asp.location
  service_plan_id     = azurerm_service_plan.vuln_asp.id

  # VULNERABILITY: HTTPS Only disabled
  https_only          = false 
  
  # VULNERABILITY: Client Certificate (mTLS) disabled
  client_certificate_enabled = false

  site_config {
    # VULNERABILITY: FTP allowed instead of FTPS Only
    ftps_state = "AllAllowed"
    
    application_stack {
      # VULNERABILITY: Downlevel PHP version used
      php_version = "7.4"
    }
  }
}

# ----------------------------------------------------------------------------------
# SQL AND MONITOR RESOURCES (No Auditing, TDE, Defender)
# ----------------------------------------------------------------------------------
# VULNERABILITY: SQL Server creation is blocked by Azure free-tier constraints. 
# Skipping explicit SQL deployment to allow the rest of the vulnerable environment to succeed.
# resource "azurerm_mssql_server" "vuln_sql" {
#   name                         = "vuln-sqlv2-${random_id.suffix.hex}"
#   resource_group_name          = azurerm_resource_group.vuln_rg.name
#   location                     = "West Europe" 
#   version                      = "12.0"
#   administrator_login          = "sqladmin"
#   administrator_login_password = "P@ssw0rd1234!!!!"
# }

# resource "azurerm_mssql_database" "vuln_sqldb" {
#   name           = "vuln-db"
#   server_id      = azurerm_mssql_server.vuln_sql.id
#   collation      = "SQL_Latin1_General_CP1_CI_AS"
#   sku_name       = "DW100c"
#   transparent_data_encryption_enabled = false
# }

# resource "azurerm_mssql_firewall_rule" "vuln_sql_fw" {
#   name             = "AllowPublicAzure"
#   server_id        = azurerm_mssql_server.vuln_sql.id
#   start_ip_address = "0.0.0.0"
#   end_ip_address   = "0.0.0.0"
# }

# Key Vault
resource "azurerm_key_vault" "vuln_kv" {
  name                        = "vulnkv${random_id.suffix.hex}"
  location                    = azurerm_resource_group.vuln_rg.location
  resource_group_name         = azurerm_resource_group.vuln_rg.name
  enabled_for_disk_encryption = false
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"

  # VULNERABILITY: No azurerm_monitor_diagnostic_setting linked to capture "AuditEvent" logs
}

# Log Profile (Monitor Activity Log)
resource "azurerm_monitor_log_profile" "vuln_log_profile" {
  name = "default"
  
  storage_account_id = azurerm_storage_account.vuln_storage.id

  # VULNERABILITY: Missing "Delete" action in categories
  categories = [
    "Action",
    "Write",
  ]

  # VULNERABILITY: Missing "global" in locations
  locations = [
    "eastus",
    "westus",
  ]

  # VULNERABILITY: Retention is < 365 Days
  retention_policy {
    enabled = true
    days    = 30 
  }
}

# Defender for Cloud / SQL OFF
resource "azurerm_security_center_subscription_pricing" "virtual_machines" {
  tier          = "Free" # VULNERABILITY: Not using 'Standard' for VM protection
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql_servers" {
  tier          = "Free" # VULNERABILITY: Not using 'Standard' for SQL protection
  resource_type = "SqlServers"
}

# ----------------------------------------------------------------------------------
# ENTRA ID (AZURE AD) RESOURCES 
# ----------------------------------------------------------------------------------
resource "azuread_user" "vuln_guest_admin" {
  user_principal_name = "guest_admin_${random_id.suffix.hex}@${data.azuread_domains.default.domains[0].domain_name}"
  display_name        = "Vuln Guest Admin"
  password            = "P@ssw0rd1234!!!"
}

# VULNERABILITY: Assigning a user to Global Administrator (creating multiple global admins) without MFA/conditional access enforcement
resource "azuread_directory_role" "global_admin" {
  display_name = "Global Administrator"
}

resource "azuread_directory_role_member" "global_admin_assignment" {
  role_object_id   = azuread_directory_role.global_admin.object_id
  member_object_id = azuread_user.vuln_guest_admin.object_id
}