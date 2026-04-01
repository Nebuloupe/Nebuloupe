variable "client_id" {
  description = "The Client ID of the Service Principal"
  type        = string
  default     = ""
}

variable "client_secret" {
  description = "The Client Secret of the Service Principal"
  type        = string
  sensitive   = true
  default     = ""
}

variable "tenant_id" {
  description = "The Azure Tenant ID"
  type        = string
  default     = ""
}

variable "subscription_id" {
  description = "The Azure Subscription ID"
  type        = string
  default     = ""
}