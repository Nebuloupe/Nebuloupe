provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  zone    = var.gcp_zone
}

resource "random_id" "id" {
  byte_length = 4
}

# ---------------------------------------------------------
# VPC / Network Vulnerable Configuration
# ---------------------------------------------------------

# Creates a vulnerable network where the default might be used or simulating a legacy behavior.
resource "google_compute_network" "vulnerable_vpc" {
  name                    = "vulnerable-vpc-${random_id.id.hex}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "vulnerable_subnet" {
  name                     = "vulnerable-subnet-${random_id.id.hex}"
  network                  = google_compute_network.vulnerable_vpc.self_link
  ip_cidr_range            = "10.0.0.0/24"
  region                   = var.gcp_region
  # Violates VPC private Google access and Flow logs
  private_ip_google_access = false 
  # No log_config block implies VPC flow logs are disabled
}

resource "google_compute_firewall" "vulnerable_firewall_ssh" {
  name    = "allow-ssh-all-${random_id.id.hex}"
  network = google_compute_network.vulnerable_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"] # Violates Firewall SSH Closed
}

resource "google_compute_firewall" "vulnerable_firewall_rdp" {
  name    = "allow-rdp-all-${random_id.id.hex}"
  network = google_compute_network.vulnerable_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  source_ranges = ["0.0.0.0/0"] # Violates Firewall RDP Closed
}

# ---------------------------------------------------------
# Compute Vulnerable Configuration
# ---------------------------------------------------------

resource "google_compute_instance" "vulnerable_vm" {
  name         = "vulnerable-vm-${random_id.id.hex}"
  machine_type = "e2-medium"
  zone         = var.gcp_zone

  can_ip_forward = true # Violates Compute IP Forwarding disabled

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      # Violates CSEK Disk Encryption (no disk_encryption_key specified)
    }
  }

  network_interface {
    network    = google_compute_network.vulnerable_vpc.id
    subnetwork = google_compute_subnetwork.vulnerable_subnet.id
    access_config {
      # Presence of this block assigns a Public IP (Violates VM no public IP)
    }
  }

  metadata = {
    # Violates OS Login enabled and Project-wide SSH keys disabled
    enable-oslogin         = "FALSE"
    block-project-ssh-keys = "FALSE"
    serial-port-enable     = "TRUE"  # Violates Serial port disabled
  }

  # Violates Shielded VM, vTPM, and Confidential Computing rules
  shielded_instance_config {
    enable_secure_boot          = false
    enable_vtpm                 = false
    enable_integrity_monitoring = false
  }

  confidential_instance_config {
    enable_confidential_compute = false
  }

  # Violates Default Compute SA unused (uses default SA by default if none specified or explicitly defined as default)
  service_account {
    scopes = ["cloud-platform"]
  }
}

# ---------------------------------------------------------
# Storage Vulnerable Configuration
# ---------------------------------------------------------

resource "google_storage_bucket" "vulnerable_bucket" {
  name                        = "vulnerable-bucket-${random_id.id.hex}"
  location                    = var.gcp_region
  force_destroy               = true
  uniform_bucket_level_access = false # Violates Uniform Bucket Level Access

  # Violates Object Versioning Enabled
  versioning {
    enabled = false
  }
  
  # Violates Logging enabled (no logging block)
  # Violates CMEK used sensitive data (no encryption block specified)
}

# Violates No AllUsers (public access)
resource "google_storage_bucket_iam_binding" "public_access" {
  bucket = google_storage_bucket.vulnerable_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers",
  ]
}

# ---------------------------------------------------------
# Cloud SQL Vulnerable Configuration
# ---------------------------------------------------------

resource "google_sql_database_instance" "vulnerable_sql" {
  name             = "vulnerable-sql-${random_id.id.hex}"
  database_version = "POSTGRES_14"
  region           = var.gcp_region

  settings {
    tier = "db-f1-micro"

    # Violates SQL Secure configurations
    ip_configuration {
      ipv4_enabled    = true  # Violates SQL no public IP
      require_ssl     = false # Violates require SSL/TLS
    }

    # Violates Automated Backups enabled
    backup_configuration {
      enabled = false
    }

    database_flags {
      name  = "cross_db_ownership_chaining"
      value = "on" # Violates Cross DB ownership disabled
    }

    database_flags {
      name  = "contained_database_authentication"
      value = "on" # Violates Contained DB Auth off
    }
  }
  
  deletion_protection = false
}

# ---------------------------------------------------------
# IAM Vulnerable Configuration
# ---------------------------------------------------------

resource "google_service_account" "vulnerable_sa" {
  account_id   = "vulnerable-sa-${random_id.id.hex}"
  display_name = "Vulnerable Service Account"
}

# Violates SA Keys Rotated / User Managed SA Keys minimized
resource "google_service_account_key" "vulnerable_key" {
  service_account_id = google_service_account.vulnerable_sa.name
}

# Violates IAM no primitive roles
resource "google_project_iam_binding" "primitive_editor" {
  project = var.gcp_project
  role    = "roles/editor"
  members = [
    "serviceAccount:${google_service_account.vulnerable_sa.email}"
  ]
}

# ---------------------------------------------------------
# Logging Vulnerable Configuration
# ---------------------------------------------------------

# Purposefully omitting the creation of Google Cloud Log Sinks and Metric Alerts
# This lack of configuration naturally trips rules like:
# - logging_audit_logs_enabled
# - logging_bucket_locks_on
# - logging_iam_changes_alert
# - logging_vpc_changes_alert
# - etc.