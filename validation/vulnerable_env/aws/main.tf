provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------
# S3 Vulnerable Configuration
# ---------------------------------------------------------

# Unencrypted, no versioning, no object lock, no logging bucket
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "nebuloupe-vulnerable-test-bucket-${random_id.id.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "vulnerable_bucket_pab" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "vulnerable_bucket_policy" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  # Setting policy that allows public read and write access, and s3:* to anyone, causing major violations.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWrite"
        Effect    = "Allow"
        Principal = "*"
        Action    = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      },
      {
        Sid       = "CrossAccountAccess"
        Effect    = "Allow"
        Principal = "*" # Simulating cross-account
        Action    = "s3:*"
        Resource  = "${aws_s3_bucket.vulnerable_bucket.arn}/*"
      }
    ]
  })
  
  depends_on = [aws_s3_bucket_public_access_block.vulnerable_bucket_pab]
}

# ---------------------------------------------------------
# EC2 & VPC Vulnerable Configuration
# ---------------------------------------------------------

resource "aws_vpc" "vulnerable_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "vulnerable_subnet" {
  vpc_id                  = aws_vpc.vulnerable_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true # EC2 No Public IP violation
}

resource "aws_internet_gateway" "vulnerable_igw" {
  vpc_id = aws_vpc.vulnerable_vpc.id
}

resource "aws_route_table" "vulnerable_rt" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.vulnerable_igw.id
  }
}

resource "aws_main_route_table_association" "vulnerable_main_rt" {
  vpc_id         = aws_vpc.vulnerable_vpc.id
  route_table_id = aws_route_table.vulnerable_rt.id
}

# Unrestricted Security Group (Violates DB ports, SSH, RDP)
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg"
  description = "Open to the world"
  vpc_id      = aws_vpc.vulnerable_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  ingress {
    protocol    = "-1"
    self        = true
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"] # VPC default SG closed violation
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_acl" "vulnerable_nacl" {
  vpc_id = aws_vpc.vulnerable_vpc.id

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Unencrypted EBS, termination protection disabled, detailed monitoring off, IMDSv2 not enforced, no SSM
resource "aws_instance" "vulnerable_ec2" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.vulnerable_subnet.id
  vpc_security_group_ids      = [aws_security_group.vulnerable_sg.id]
  associate_public_ip_address = true
  disable_api_termination     = false # Termination protection off
  monitoring                  = false # Detailed monitoring off

  root_block_device {
    encrypted = false
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # IMDSv2 not enforced
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "vulnerable-ec2"
  }
}

resource "aws_eip" "unused_eip" {
  domain = "vpc"
  # Violates unused EIP released
}

resource "aws_ebs_volume" "vulnerable_ebs" {
  availability_zone = aws_subnet.vulnerable_subnet.availability_zone
  size              = 10
  encrypted         = false
}

resource "aws_ebs_snapshot" "vulnerable_snapshot" {
  volume_id = aws_ebs_volume.vulnerable_ebs.id
}

# ---------------------------------------------------------
# IAM Vulnerable Configuration
# ---------------------------------------------------------
resource "aws_iam_user" "vulnerable_user" {
  name = "vulnerable-admin-user"
}

resource "aws_iam_user_policy" "vulnerable_inline_policy" {
  name = "VulnerableInlinePolicy"
  user = aws_iam_user.vulnerable_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "star_star_policy" {
  name        = "StarStarPolicy"
  description = "A vulnerable policy with *:* access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "vulnerable_user_attach" {
  user       = aws_iam_user.vulnerable_user.name
  policy_arn = aws_iam_policy.star_star_policy.arn
}

resource "aws_iam_access_key" "vulnerable_access_key" {
  user = aws_iam_user.vulnerable_user.name
  # This key will not be rotated, violating IAM keys rotated 90 days.
}

resource "aws_iam_account_password_policy" "weak_policy" {
  minimum_password_length        = 6
  require_lowercase_characters   = false
  require_numbers                = false
  require_uppercase_characters   = false
  require_symbols                = false
  allow_users_to_change_password = true
  password_reuse_prevention      = 1
  max_password_age               = 0
}

# ---------------------------------------------------------
# RDS Vulnerable Configuration
# ---------------------------------------------------------
resource "aws_db_instance" "vulnerable_rds" {
  allocated_storage          = 20
  engine                     = "mysql"
  engine_version             = "8.0"
  instance_class             = "db.t3.micro"
  username                   = "admin"
  password                   = "weakpassword123"
  parameter_group_name       = "default.mysql8.0"
  skip_final_snapshot        = true
  publicly_accessible        = true   # Violates RDS publicly accessible
  storage_encrypted          = false  # Violates RDS storage encrypted
  multi_az                   = false  # Violates RDS multi AZ
  auto_minor_version_upgrade = false  # Violates Auto minor upgrades
}

# ---------------------------------------------------------
# CloudTrail (Logging) Vulnerable Config
# ---------------------------------------------------------
resource "aws_cloudtrail" "vulnerable_trail" {
  name                          = "vulnerable-trail"
  s3_bucket_name                = aws_s3_bucket.vulnerable_bucket.id
  is_multi_region_trail         = false # Violates multi-region
  enable_log_file_validation    = false # Violates log validation
  kms_key_id                    = null  # Violates KMS encryption
  
  depends_on = [aws_s3_bucket_policy.vulnerable_bucket_policy]
}

resource "random_id" "id" {
  byte_length = 4
}
