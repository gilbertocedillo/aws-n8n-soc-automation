#!/bin/bash
set -euxo pipefail
# Bootstrap - Amazon Linux 2023
# 1) Updates  2) CloudWatch Agent  3) Wazuh Agent (optional)  4) Custom monitor

PROJECT="${project}"
REGION="${region}"
WEBHOOK_URL="${webhook_url}"

dnf update -y
dnf install -y python3 python3-pip amazon-cloudwatch-agent auditd inotify-tools

pip3 install requests pyyaml watchdog

# --- CloudWatch Agent config ---
mkdir -p /opt/aws/amazon-cloudwatch-agent/etc /var/log/soc-lab
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'JSON'
{
  "agent": {"metrics_collection_interval": 60, "run_as_user": "root"},
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {"file_path": "/var/log/secure", "log_group_name": "/soc-lab/ec2", "log_stream_name": "secure-{instance_id}"},
          {"file_path": "/var/log/httpd/access_log", "log_group_name": "/soc-lab/ec2", "log_stream_name": "http-access-{instance_id}"},
          {"file_path": "/var/log/soc-lab/alerts.json", "log_group_name": "/soc-lab/ec2", "log_stream_name": "alerts-{instance_id}"}
        ]
      }
    }
  },
  "metrics": {"namespace": "soc-lab", "metrics_collected": {"mem": {}, "disk": {}, "netstat": {}}}
}
JSON
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json || true

# --- auditd: FIM + privileged commands ---
cat > /etc/audit/rules.d/soc-lab.rules <<'RULES'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /usr/bin -p wa -k binaries
-a always,exit -F arch=b64 -S execve -k exec
RULES
systemctl enable --now auditd || true

# --- Webhook URL for monitor (not baked into code in prod - use SSM Parameter) ---
mkdir -p /opt/soc-monitor
echo "$WEBHOOK_URL" > /opt/soc-monitor/.webhook_url
chmod 600 /opt/soc-monitor/.webhook_url

# Monitor service is installed from agent/monitor.py by the deploy script
# See ../scripts/deploy-agent.sh - or copy monitor.py here manually:
#   scp / SSM send-command with monitor.py -> /opt/soc-monitor/monitor.py
#   systemctl enable --now soc-monitor

echo "Bootstrap complete $(date -u --iso-8601=seconds)" >> /var/log/soc-lab/bootstrap.log
