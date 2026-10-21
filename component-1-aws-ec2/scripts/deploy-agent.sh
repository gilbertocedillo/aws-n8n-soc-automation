#!/bin/bash
# Deploy monitor.py to a running EC2 via SSM (no SSH needed)
# Usage: INSTANCE_ID=i-xxx REGION=us-east-1 WEBHOOK_URL=https://... ./deploy-agent.sh
set -euo pipefail
: "${INSTANCE_ID:?}" : "${REGION:=us-east-1}" : "${WEBHOOK_URL:?}"
echo "Deploy via SSM send-command - copy agent/monitor.py content to /opt/soc-monitor/monitor.py on the instance"
echo "Simplest manual path (SSM Session Manager):"
echo "  aws ssm start-session --target $INSTANCE_ID --region $REGION"
echo "  # on instance:"
echo "  sudo mkdir -p /opt/soc-monitor /var/log/soc-lab"
echo "  sudo nano /opt/soc-monitor/monitor.py   # paste monitor.py"
echo "  echo '$WEBHOOK_URL' | sudo tee /opt/soc-monitor/.webhook_url && sudo chmod 600 /opt/soc-monitor/.webhook_url"
echo "  sudo cp soc-monitor.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now soc-monitor"
echo "  sudo systemctl status soc-monitor && sudo tail -f /var/log/soc-lab/alerts.json"
