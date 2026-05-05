terraform {
  required_version = ">= 1.3.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  zone    = var.gcp_zone
}

resource "random_id" "suffix" {
  byte_length = 3
}

resource "google_project_service" "compute_api" {
  project            = var.gcp_project
  service            = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "storage_api" {
  project            = var.gcp_project
  service            = "storage.googleapis.com"
  disable_on_destroy = false
}

resource "google_compute_network" "vuln_vpc" {
  name                    = "vuln-vpc-${random_id.suffix.hex}"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.compute_api]
}

resource "google_compute_subnetwork" "vuln_subnet" {
  name          = "vuln-subnet-${random_id.suffix.hex}"
  region        = var.gcp_region
  network       = google_compute_network.vuln_vpc.id
  ip_cidr_range = "10.10.0.0/24"
}

resource "google_compute_firewall" "open_ssh" {
  name    = "allow-ssh-world-${random_id.suffix.hex}"
  network = google_compute_network.vuln_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["vuln-vm"]
}

resource "google_compute_instance" "vuln_vm" {
  name         = "vuln-vm-${random_id.suffix.hex}"
  machine_type = "e2-micro"
  zone         = var.gcp_zone
  tags         = ["vuln-vm"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.vuln_subnet.id

    # Presence of this block assigns an external public IP.
    access_config {}
  }

  metadata = {
    enable-oslogin = "FALSE"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

resource "google_storage_bucket" "public_bucket" {
  name                        = "vuln-public-bucket-${random_id.suffix.hex}"
  location                    = var.gcp_region
  force_destroy               = true
  # Some org policies enforce UBLA. Keep bucket public through IAM binding below.
  uniform_bucket_level_access = true
  depends_on                  = [google_project_service.storage_api]

  versioning {
    enabled = false
  }
}

resource "google_storage_bucket_iam_binding" "public_read" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers"
  ]
}
