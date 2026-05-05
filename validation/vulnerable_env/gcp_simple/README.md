# GCP Simple Vulnerable Environment (Terraform)

This folder contains a deliberately insecure Terraform environment for security testing.

Included misconfigurations:
- Public GCS bucket via allUsers IAM binding
- SSH (TCP/22) open to 0.0.0.0/0
- VM with external public IP
- VM metadata with OS Login disabled
- Broad cloud-platform scope on VM service account

## Usage

1. Configure ADC credentials:
   - gcloud auth application-default login
2. Initialize Terraform:
   - terraform init
3. Provide variables:
   - copy terraform.tfvars.example terraform.tfvars
   - edit gcp_project
4. Deploy:
   - terraform apply
5. Destroy when done:
   - terraform destroy

Use only in authorized, isolated test projects.
