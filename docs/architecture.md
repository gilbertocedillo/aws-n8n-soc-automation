# Architecture

```
[Attacker / Internet]
        |
        v
[EC2 - Hardened]  SG: 80/443 world, 22 = your /32 or CLOSED (SSM), IMDSv2, encrypted EBS
  |-- CloudWatch Agent --> CloudWatch Logs (/soc-lab/ec2, 30d retention)
  |-- Wazuh Agent (alt) --> Wazuh Manager (FIM/syscheck)
  |-- monitor.py
  |     - tail /var/log/secure        -> SSH brute force / failed logins
  |     - tail httpd/access_log       -> SQLi, XSS, traversal, scanners
  |     - SHA256 poll (5s) FIM paths  -> /etc/passwd, shadow, sudoers, sshd_config
  |     -> alerts.json (local forensic copy FIRST)
  |     -> POST JSON ------+
  v                        |
[Component 2: n8n] <-------+
  1 Webhook /soc-alert
  2 Code: extract + validate IP
  3 VirusTotal API v3: /ip_addresses/{ip}
  4 Code: enrich context
  5 LLM (gpt-4o-mini): analysis JSON {severity, confidence, action}
  6 Code: gate -> isolate ONLY if true_positive && confidence>=70 && (critical || high+isolate)
  7 IF
     |-- YES -> 8a AWS Lambda: ModifyInstanceAttribute -> Quarantine SG (no in/out)
     +-- ------> 8b Discord/Slack webhook: embed with severity, VT, action
  9 Respond 200 {ok, severity, action, isolated}
  
Latency budget (<5s): webhook 0.1 + VT 0.8 + LLM 1.2 + Lambda 0.6 + Discord 0.4 = ~3.1s typical
```

## Security decisions
- **Isolation != termination.** Quarantine SG preserves the disk/memory for forensics.
- **LLM never acts alone.** Code gate (deterministic) enforces confidence/severity thresholds after the LLM.
- **Least privilege everywhere:** EC2 role = only its log group; Lambda = only ModifyInstanceAttribute on allowlisted instance; n8n AWS cred = only Invoke that Lambda.
- **Fail safe:** If n8n/VT/LLM is down, EC2 still writes alerts.json + CloudWatch. No alert is lost.
- **Secrets:** No keys in code. `.env` / n8n env vars / Secrets Manager. `.env.example` only.

## MITRE ATT&CK coverage
| Detection | Technique |
|---|---|
| SSH brute force | T1110.001 Brute Force: Password Guessing |
| HTTP SQLi / exploit | T1190 Exploit Public-Facing Application |
| FIM system files | T1543 Create/Modify System Process / persistence via account manipulation |
