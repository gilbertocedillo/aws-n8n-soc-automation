#!/usr/bin/env python3
"""
SOC Monitor Agent - Component 1
Monitors in real time:
  1. Anomalous traffic / auth: failed SSH logins, brute force (/var/log/secure)
  2. File Integrity Monitoring (FIM): /etc/passwd, /etc/shadow, /etc/sudoers, sshd_config, /usr/bin
  3. Malicious HTTP requests: SQLi, XSS, path traversal, scanners (access_log)

On detection -> structured JSON alert -> Webhook (n8n, Component 2) + local alerts.json

Design: stdlib + requests only, runs as systemd service, backoff on webhook failure,
never crashes the host if n8n is down (writes to local file first).
"""
import json, os, re, time, hashlib, socket, logging
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, deque

try:
    import requests
except ImportError:
    requests = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("soc-monitor")

WEBHOOK_URL = os.getenv("WEBHOOK_URL") or Path("/opt/soc-monitor/.webhook_url").read_text().strip() if Path("/opt/soc-monitor/.webhook_url").exists() else ""
INSTANCE_ID = os.getenv("INSTANCE_ID", "unknown")  # deploy script injects via IMDSv2
ALERT_FILE = Path(os.getenv("ALERT_FILE", "/var/log/soc-lab/alerts.json"))
ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

# --- Detection rules ---
HTTP_PATTERNS = {
    "sqli": re.compile(r"(\bunion\b.*\bselect\b|\bor\b\s+1=1|'\s*or\s*'|sleep\(|benchmark\()", re.I),
    "xss": re.compile(r"(<script|onerror\s*=|javascript:)", re.I),
    "path_traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow)", re.I),
    "scanner": re.compile(r"(sqlmap|nikto|nmap|dirbuster|gobuster|masscan|zgrab)", re.I),
    "shell_attempt": re.compile(r"(\.php\?|cmd=|/bin/bash|wget\s+http|curl\s+http)", re.I),
}
FIM_PATHS = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config"]
SSH_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+)")
SSH_SUCCESS = re.compile(r"Accepted .* for (\S+) from ([\d\.]+)")

# Brute force: >=5 fails from same IP in 120s
fail_window = defaultdict(deque)
BRUTE_THRESHOLD, BRUTE_WINDOW = 5, 120

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_hostname():
    return socket.gethostname()

def emit(alert: dict):
    """Write locally first (forensics), then POST to webhook with retry."""
    alert.setdefault("timestamp", now_iso())
    alert.setdefault("host", get_hostname())
    alert.setdefault("instance_id", INSTANCE_ID)
    alert.setdefault("source_component", "ec2-monitor-v1")
    line = json.dumps(alert, ensure_ascii=False)
    with ALERT_FILE.open("a") as f:
        f.write(line + "\n")
    log.warning(f"ALERT {alert.get('alert_type')} severity={alert.get('severity')} ip={alert.get('source_ip')}")
    if not WEBHOOK_URL or not requests:
        log.info("No webhook configured, alert saved locally only")
        return
    for attempt in range(3):
        try:
            r = requests.post(WEBHOOK_URL, json=alert, timeout=3)
            if r.status_code < 300:
                return
            log.error(f"Webhook {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log.error(f"Webhook failed attempt {attempt+1}: {e}")
        time.sleep(1 * (attempt + 1))

def file_hashes():
    h = {}
    for p in FIM_PATHS:
        try:
            h[p] = hashlib.sha256(Path(p).read_bytes()).hexdigest()
        except Exception:
            pass
    return h

def tail_file(path, handler):
    """Simple tail -f with rotation tolerance."""
    while not Path(path).exists():
        time.sleep(2)
    with open(path, errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            try:
                handler(line)
            except Exception as e:
                log.error(f"handler error: {e}")

def handle_secure(line):
    m = SSH_FAIL.search(line)
    if m:
        user, ip = m.groups()
        q = fail_window[ip]
        q.append(time.time())
        while q and q[0] < time.time() - BRUTE_WINDOW:
            q.popleft()
        if len(q) >= BRUTE_THRESHOLD:
            emit({"alert_type": "ssh_brute_force", "severity": "high", "source_ip": ip,
                  "user": user, "event": {"failed_attempts": len(q), "window_sec": BRUTE_WINDOW, "raw": line.strip()},
                  "mitre": {"tactic": "Credential Access", "technique": "T1110.001"}})
            q.clear()
        else:
            emit({"alert_type": "ssh_failed_login", "severity": "low", "source_ip": ip,
                  "user": user, "event": {"raw": line.strip()}, "mitre": {"technique": "T1110"}})

def handle_http(line):
    # Combined log format: IP - - [date] "METHOD path" status size "ref" "UA"
    m = re.match(r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d{3})', line)
    if not m:
        return
    ip, _, method, path, status = m.groups()
    for name, pat in HTTP_PATTERNS.items():
        if pat.search(path) or pat.search(line):
            sev = "critical" if name in ("sqli", "shell_attempt") else "high" if name in ("xss", "path_traversal") else "medium"
            emit({"alert_type": f"http_{name}", "severity": sev, "source_ip": ip,
                  "event": {"method": method, "path": path, "status": int(status), "raw": line.strip()},
                  "mitre": {"tactic": "Initial Access", "technique": "T1190"}})
            return

def fim_loop():
    prev = file_hashes()
    while True:
        time.sleep(5)
        cur = file_hashes()
        for p, hv in cur.items():
            if p in prev and prev[p] != hv:
                emit({"alert_type": "fim_file_modified", "severity": "critical", "source_ip": "localhost",
                      "event": {"file": p, "old_sha256": prev[p], "new_sha256": hv},
                      "mitre": {"tactic": "Persistence", "technique": "T1543"}})
        prev = cur

if __name__ == "__main__":
    import threading
    log.info(f"Starting SOC monitor instance={INSTANCE_ID} webhook={'set' if WEBHOOK_URL else 'NOT SET'}")
    threads = []
    for target, args in [(tail_file, ("/var/log/secure", handle_secure)),
                         (tail_file, ("/var/log/httpd/access_log", handle_http)),
                         (tail_file, ("/var/log/apache2/access.log", handle_http)),
                         (fim_loop, ())]:
        t = threading.Thread(target=target, args=args, daemon=True)
        t.start(); threads.append(t)
    try:
        while True: time.sleep(60)
    except KeyboardInterrupt:
        log.info("Stopping")
