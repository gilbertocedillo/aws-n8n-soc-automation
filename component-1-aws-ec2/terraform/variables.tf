variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix for all resources"
  type        = string
  default     = "soc-lab"
}

variable "environment" {
  type    = string
  default = "lab"
}

variable "instance_type" {
  description = "EC2 type - t3.micro is Free Tier eligible"
  type        = string
  default     = "t3.micro"
}

variable "allowed_ssh_cidr" {
  description = "YOUR public IP in /32 - NEVER use 0.0.0.0/0 for SSH. Get it with: curl ifconfig.me"
  type        = string
  # No default on purpose: forces least-privilege explicit input
}

variable "webhook_url" {
  description = "n8n Webhook URL that will receive JSON alerts (Component 2)"
  type        = string
  sensitive   = true
}

variable "key_pair_name" {
  description = "Existing EC2 Key Pair name for SSH (optional if you use SSM Session Manager - recommended)"
  type        = string
  default     = ""
}

variable "enable_ssm" {
  description = "Use SSM Session Manager instead of SSH - recommended, allows closing port 22 completely"
  type        = bool
  default     = true
}
