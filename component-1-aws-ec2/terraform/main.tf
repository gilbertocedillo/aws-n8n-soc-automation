terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Latest Amazon Linux 2023 AMI (SSM parameter, no hardcoded AMI) ---
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_vpc" "default" {
  default = true
}

# --- EC2 Hardened ---
resource "aws_instance" "monitored" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2.name
  key_name               = var.key_pair_name != "" ? var.key_pair_name : null

  # IMDSv2 ONLY - blocks SSRF credential theft (169.254.169.254)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Encrypted root volume
  root_block_device {
    encrypted             = true
    volume_type           = "gp3"
    volume_size           = 20
    delete_on_termination = true
  }

  # Bootstrap: installs CloudWatch Agent + Wazuh agent + custom monitor
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    webhook_url = var.webhook_url
    project     = var.project_name
    region      = var.aws_region
  })

  tags = {
    Name        = "${var.project_name}-monitored-ec2"
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
