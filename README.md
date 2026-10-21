# 🛡️ SOC Automation: AWS EC2 Monitoring + AI Auto-Response (n8n)

End-to-end mini-SOC: a hardened AWS EC2 instance detects attacks in real time and emits structured JSON alerts, and an AI-driven n8n workflow enriches them with threat intelligence, analyzes them with an LLM, **automatically isolates the instance in <5 seconds**, and notifies the security team on Discord/Slack.

> Portfolio project by **Gilberto A. Cedillo Soto (Abisaíd)** — Cybersecurity, BYU-Idaho (Class of 2027)
> `AWS` · `Terraform` · `Wazuh / CloudWatch Agent` · `Python` · `n8n` · `VirusTotal API` · `LLM` · `MITRE ATT&CK`

📐 Full diagram: [docs/architecture.md](docs/architecture.md)

---

## Component 1 — Hardened EC2 + Real-Time Detection (`component-1-aws-ec2/`)

- **Terraform IaC** — EC2 (Amazon Linux 2023), encrypted EBS, **IMDSv2 required**
- **Least Privilege Security Groups** — SSH only from your `/32` or **closed entirely** (SSM Session Manager), HTTP/HTTPS only inbound, narrow egress. Plus a **Quarantine SG** (no traffic) for isolation
- **Least Privilege IAM** — custom policy scoped to *only* this project's CloudWatch Log Group + namespace — no broad AWS managed policies
- **Log agent** — CloudWatch Agent config included (+ Wazuh agent `ossec.conf` alternative with FIM/syscheck)
- **`monitor.py`** — real-time detection agent:
  | Detection | Source | MITRE |
  |---|---|---|
  | SSH brute force (≥5 fails / 120s) + failed logins | `/var/log/secure` | T1110.001 |
  | SQLi, XSS, path traversal, scanners, shell attempts | HTTP access log | T1190 |
  | File Integrity Monitoring (SHA256, 5s poll) | `/etc/passwd, shadow, sudoers, sshd_config` | T1543 |
- **Output:** structured **JSON alert** → local `alerts.json` (forensic-first) → **Webhook POST** to n8n, with retry/backoff

**Deploy:**
```bash
cd component-1-aws-ec2/terraform
cp ../../.env.example ../../.env   # fill your values, never commit .env
terraform init
terraform apply -var="allowed_ssh_cidr=$(curl -s ifconfig.me)/32" -var="webhook_url=https://YOUR-N8N/webhook/soc-alert"
# outputs: instance_id, public_ip, quarantine_security_group_id  -> save the last one for Component 2
chmod +x ../scripts/test-alerts.sh
../scripts/test-alerts.sh <EC2_PUBLIC_IP> <WEBHOOK_URL>   # generates SQLi/traversal test alerts
```

Example alert: [examples/sample-alert.json](examples/sample-alert.json)

---

## Component 2 — n8n AI Auto-Response Workflow (`component-2-n8n/`)

Importable workflow: [`workflow/soc-ai-response-workflow.json`](component-2-n8n/workflow/soc-ai-response-workflow.json)

```
Webhook → Extract IP → VirusTotal reputation → Enrich → LLM analysis (JSON)
       → Deterministic gate (confidence ≥70 + high/critical) 
       → [IF] AWS Lambda isolates EC2 (Quarantine SG) → Discord/Slack notification → Respond
```

- **VirusTotal API v3** — IP reputation (`malicious/suspicious`, country, AS owner)
- **LLM triage** — fast small model (`gpt-4o-mini`, swappable for Claude Haiku / Ollama), strict JSON schema prompt: [prompts/llm-incident-analysis.md](component-2-n8n/prompts/llm-incident-analysis.md)
- **Isolation Lambda** — [`lambda/isolate_instance.py`](component-2-n8n/lambda/isolate_instance.py): swaps the instance's SGs for the Quarantine SG. **Preserves the instance for forensics — never terminates it.** Allowlist + `DRY_RUN` mode included
- **Latency budget ~3.1s typical** (target <5s): VT 0.8s + LLM 1.2s + Lambda 0.6s + Discord 0.4s

**Setup:**
1. In n8n: **Workflows → Import from File** → select the workflow JSON, Activate it
2. Set n8n env vars: `VIRUSTOTAL_API_KEY`, `OPENAI_API_KEY`, `DISCORD_WEBHOOK_URL` (or Slack), `ISOLATION_LAMBDA_ARN`
3. Deploy the Lambda (console or SAM/zip of `isolate_instance.py`) with env vars `QUARANTINE_SG_ID` (from Component 1 output) + `MONITORED_INSTANCE_ID`, `DRY_RUN=true` for your first test
4. Test: `curl -X POST https://YOUR-N8N/webhook/soc-alert -H 'Content-Type: application/json' -d @examples/sample-alert.json`
5. Verify: n8n Executions (all green) → Discord/Slack message arrives → in AWS Console the EC2 SG changed to Quarantine (set `DRY_RUN=false` for real isolation)

**Rollback from isolation:**
```bash
aws ec2 modify-instance-attribute --instance-id i-xxx --groups sg-ORIGINAL --region us-east-1
# original SG id is logged in the Lambda result + CloudWatch
```

---

## Security Notes
- No secrets in code — env vars / Secrets Manager only. `.gitignore` covers `.env`, tfstate, keys.
- The LLM **proposes**, a deterministic code gate **decides**, the Lambda **executes only on an allowlisted instance**.
- If n8n / VT / LLM is down, the EC2 still logs to `alerts.json` + CloudWatch — no alert is lost.

## Roadmap
- [ ] Block source IP at SG/NACL level (in addition to instance isolation)
- [ ] VirusTotal result caching (10 min / IP) for high volume
- [ ] Store incidents in a DB (Supabase/Postgres) + weekly LLM summary report
- [ ] GuardDuty + Security Hub findings as a second alert source

## License
MIT
