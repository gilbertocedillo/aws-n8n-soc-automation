output "instance_id" {
  value = aws_instance.monitored.id
}

output "instance_public_ip" {
  value = aws_instance.monitored.public_ip
}

output "security_group_id" {
  value = aws_security_group.ec2.id
}

output "quarantine_security_group_id" {
  description = "Pass this to Component 2 Lambda env var QUARANTINE_SG_ID"
  value       = aws_security_group.quarantine.id
}

output "ssh_or_ssm_hint" {
  value = var.enable_ssm ? "Connect via: aws ssm start-session --target ${aws_instance.monitored.id} --region ${var.aws_region}" : "Connect via: ssh -i <your-key.pem> ec2-user@${aws_instance.monitored.public_ip}"
}
