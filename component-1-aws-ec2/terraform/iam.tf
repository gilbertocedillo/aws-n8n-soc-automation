# ============================================================
# IAM - Least Privilege
# The EC2 role can ONLY: write its own logs/metrics to CloudWatch
# and (if SSM enabled) be managed via Session Manager.
# It CANNOT: read S3, modify EC2, assume other roles, access secrets.
# ============================================================

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "ec2" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Custom scoped policy - NOT AmazonCloudWatchAgentServerPolicy (too broad)
resource "aws_iam_policy" "ec2_least_privilege" {
  name        = "${var.project_name}-ec2-least-privilege"
  description = "Only CloudWatch Logs/Metrics for this project + SSM core if enabled"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudWatchLogsScoped"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.project_name}/*:*"
      },
      {
        Sid    = "CloudWatchMetricsScoped"
        Effect = "Allow"
        Action = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = { "cloudwatch:namespace" = var.project_name }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "custom" {
  role       = aws_iam_role.ec2.name
  policy_arn = aws_iam_policy.ec2_least_privilege.arn
}

# Optional but recommended: SSM Session Manager (no SSH port needed)
resource "aws_iam_role_policy_attachment" "ssm" {
  count      = var.enable_ssm ? 1 : 0
  role       = aws_iam_role.ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2.name
}

# --- CloudWatch Log Group with retention (cost + hygiene) ---
resource "aws_cloudwatch_log_group" "app" {
  name              = "/${var.project_name}/ec2"
  retention_in_days = 30
}
