variable "gcp_project" {
  description = "The Google Cloud project ID."
  type        = string
  default     = "nebuloupe-vulnerable-test"
}

variable "gcp_region" {
  description = "The Google Cloud region to deploy resources."
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "The Google Cloud zone."
  type        = string
  default     = "us-central1-a"
}