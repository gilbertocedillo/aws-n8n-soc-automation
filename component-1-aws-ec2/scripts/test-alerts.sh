#!/bin/bash
# Run ON the EC2 (or against it) to generate test alerts and verify the full pipeline
# Usage: ./test-alerts.sh <EC2_PUBLIC_IP> <WEBHOOK_URL>
set -x
IP="${1:?EC2 IP required}"
WEBHOOK="${2:-}"

echo "== 1. Malicious HTTP: SQLi attempt =="
curl -s "http://${IP}/?id=1'%20OR%20'1'='1%20UNION%20SELECT%20*%20FROM%20users" -A "sqlmap/1.7" || true

echo "== 2. Path traversal =="
curl -s "http://${IP}/../../../../etc/passwd" || true

echo "== 3. Direct webhook test (bypasses EC2, tests n8n only) =="
if [ -n "$WEBHOOK" ]; then
  curl -s -X POST "$WEBHOOK" -H "Content-Type: application/json" -d '{
    "timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
    "alert_type":"ssh_brute_force","severity":"high","source_ip":"185.220.101.47",
    "host":"soc-lab-ec2","instance_id":"i-TEST",
    "event":{"failed_attempts":12,"window_sec":120,"raw":"Failed password for root from 185.220.101.47"},
    "mitre":{"tactic":"Credential Access","technique":"T1110.001"}
  }'
  echo
fi
echo "Check: tail -f /var/log/soc-lab/alerts.json (on EC2) + n8n Executions + Discord/Slack"
echo "SSH brute force test (do manually, will fail auth): for i in 1 2 3 4 5 6; do ssh -o BatchMode=yes -o ConnectTimeout=3 invaliduser@${IP} || true; done"
