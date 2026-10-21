# Interview Defense Guide — How to talk about this project truthfully

## The honest framing (this is your right to claim it)

You **specified, designed and directed** this project: the requirements were yours
verbatim — hardened EC2 with least-privilege SG/IAM, log agent monitoring anomalous
traffic + FIM + malicious HTTP emitting JSON via webhook; and an n8n AI workflow with
VirusTotal + LLM + automatic isolation + Discord/Slack in <5s.

You used an AI assistant as a pair-programming / implementation tool — the same way
engineers use Copilot, ChatGPT or Claude at work. That is a normal, disclosable
workflow in 2026. What makes a project "yours" in an interview is NOT who typed each
line — it's whether you can **explain it, run it, break it, and extend it**.

**Say this if asked "did you build this?":**
> "Yes — I designed the architecture and requirements, and I built it using AI
> assistance for implementation, which I reviewed and validated. I can walk you
> through every component and the design decisions."

**Never say:** "I hand-coded every line from scratch" / "I deployed this in
production" — neither is true, and a technical interviewer will find out in 2
follow-up questions. Honesty + understanding beats a bigger claim.

## 30-second pitch (English, for interviews)

> "I built a mini-SOC automation project. A hardened EC2 instance — least-privilege
> security groups and IAM, IMDSv2, encrypted disk — runs a Python detection agent
> that watches SSH logs for brute force, HTTP logs for SQLi and XSS, and system
> files for integrity changes. Every detection becomes a structured JSON alert sent
> by webhook to n8n. There, the IP is enriched with VirusTotal, an LLM triages the
> incident and returns severity and confidence in JSON, and if it's high or critical
> with at least 70% confidence, a Lambda automatically isolates the instance by
> swapping its security group for a quarantine group, and the team gets a Discord
> alert. End to end it's about 3 seconds."

## 5 design decisions you must be able to defend

1. **Why least-privilege IAM with a custom policy, not the AWS managed one?**
   AmazonCloudWatchAgentServerPolicy is broader than needed. My policy only allows
   logs/metrics on *this project's* log group/namespace. If the instance is
   compromised, the attacker inherits almost nothing.

2. **Why IMDSv2 required?** IMDSv1 lets an SSRF bug steal instance credentials from
   169.254.169.254. Requiring a token + hop limit 1 kills that attack class.

3. **Why isolate with a quarantine SG instead of terminating/stopping?**
   Forensics. Isolation cuts network access in ~1s but preserves disk and state
   for investigation. Termination destroys evidence.

4. **Why doesn't the LLM decide alone?** LLMs hallucinate and can be prompt-injected
   via log data. The LLM *proposes*; a deterministic code gate decides (confidence
   ≥70 + severity high/critical + true positive), and the Lambda only acts on an
   allowlisted instance, with a DRY_RUN mode.

5. **Why write the alert to a local file before the webhook?** If n8n or the network
   is down, no alert is lost — forensic-first, then delivery with retry/backoff.

## Likely technical questions

- **How does brute-force detection work?** Sliding window: ≥5 failed SSH logins
  from the same IP in 120s → high severity alert (MITRE T1110.001).
- **How does FIM work?** SHA-256 of /etc/passwd, shadow, sudoers, sshd_config polled
  every 5s; any change = critical (T1543). Production alternative: Wazuh syscheck
  (config included in the repo) or auditd — both are wired in user_data.
- **What if VirusTotal is down / rate-limited?** The workflow continues with
  `vt.skipped=true`; the LLM gate gets stricter data, and low-confidence cases go
  to monitor/escalate, not isolation.
- **How is <5s achieved?** Small fast LLM (gpt-4o-mini), 3s VT timeout, parallel-
  friendly single pass; budget: VT 0.8 + LLM 1.2 + Lambda 0.6 + Discord 0.4 ≈ 3.1s.
- **What's missing / what would you add?** IP blocking at NACL level, VT caching,
  incident DB, GuardDuty as a second source — it's in the README roadmap. Admitting
  limits *increases* credibility.

## Before any interview: do these 4 hands-on tasks (this is what makes it yours)

1. Run `terraform plan` locally and read every resource it would create.
2. Read `monitor.py` end to end; change ONE detection (e.g. brute-force threshold
   5 → 3), commit it yourself with your own commit message.
3. Import the n8n workflow, send `examples/sample-alert.json` with curl, watch an
   execution flow through the nodes.
4. Be able to draw the architecture (docs/architecture.md) on a whiteboard from
   memory in 2 minutes.

After those, there is no asterisk: you understand, modified, and operated it.
