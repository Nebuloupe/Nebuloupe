output "vuln_vm_name" {
  value = google_compute_instance.vuln_vm.name
}

output "vuln_vm_public_ip" {
  value = google_compute_instance.vuln_vm.network_interface[0].access_config[0].nat_ip
}

output "public_bucket_name" {
  value = google_storage_bucket.public_bucket.name
}
