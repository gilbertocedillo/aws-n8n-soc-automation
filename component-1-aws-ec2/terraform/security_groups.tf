# ============================================================
# Security Groups - Least Privilege
# Principle: NO 0.0.0.0/0 inbound except 80/443 if it's a web server.
# SSH is restricted to ONE /32 OR disabled entirely with SSM.
# ============================================================

resource "aws_security_group" "ec2" {
  name        = "${var.project_name}-ec2-sg"
  description = "Least-privilege SG for monitored EC2"
  vpc_id      = data.aws_vpc.default.id

  # HTTP - only if serving a web app / lab target
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # SSH - ONLY from your IP /32, and ONLY if SSM is disabled
  dynamic "ingress" {
    for_each = var.enable_ssm ? [] : [1]
    content {
      description = "SSH restricted to operator IP"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.allowed_ssh_cidr]
    }
  }

  # Egress: only what's needed - DNS, HTTPS (updates, CloudWatch, webhook), NTP
  egress {
    description = "HTTPS egress - updates, AWS APIs, webhook"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "HTTP egress - package repos (AL2023 uses HTTPS mostly, kept narrow)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS UDP"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS TCP"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-ec2-sg" }
}

# --- Quarantine SG: used by the isolation Lambda (Component 2) ---
# NO ingress, NO egress except DNS for logging. Applying this = isolation.
resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine-sg"
  description = "QUARANTINE - No traffic in/out. Applied automatically by n8n + Lambda on high severity"
  vpc_id      = data.aws_vpc.default.id

  # Intentionally NO ingress rules
  # Only minimal egress for DNS so logs still resolve, remove if you want total isolation
  egress {
    description = "DNS only for forensic logging"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-quarantine-sg" }
}
