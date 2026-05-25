"""
Boundry.AI - Critical Alert Monitor
=====================================
Runs every 15 minutes via Windows Task Scheduler.
Scans for new HIGH/CRITICAL threats since the last check.

On CRITICAL threat:  emails Jason immediately + sends client reassurance email
On HIGH threat:      emails Jason only (client gets it in the monthly report)

Clients never see this tool. They receive a calm, professional email that says
their security team is handling it. That IS the product.

Setup:
    1. Set GMAIL_APP_PASSWORD environment variable (see PowerShell profile)
    2. Run:  python alert_monitor.py --schedule
       (adds a Task Scheduler entry to run every 15 minutes automatically)
    3. To test immediately:  python alert_monitor.py --test

Environment variables:
    GMAIL_APP_PASSWORD    16-char Gmail App Password for json.c.morgan@gmail.com
"""

import os
import re
import json
import smtplib
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent
LOG_PATH     = BASE_DIR / "flask_security.log"
CLIENTS_FILE = BASE_DIR / "clients.json"
STATE_FILE   = BASE_DIR / "alert_state.json"   # tracks last check + alerted events

JASON_EMAIL  = "json.c.morgan@gmail.com"
GMAIL_PASS   = os.environ.get("GMAIL_APP_PASSWORD", "")

BRUTE_THRESHOLD  = 3
CRITICAL_THREATS = {"PRIVILEGE_ESCALATION", "CREDENTIAL_STUFFING"}
HIGH_THREATS     = {"BRUTE_FORCE", "SQL_INJECTION_ATTEMPT", "XSS_ATTEMPT",
                    "DIRECTORY_TRAVERSAL", "PASSWORD_SPRAY", "ACCOUNT_ENUMERATION",
                    "SUSPICIOUS_LOGIN"}

MITRE_MAP = {
    "BRUTE_FORCE":           {"id": "T1110",     "name": "Brute Force"},
    "SQL_INJECTION_ATTEMPT": {"id": "T1190",     "name": "Exploit Public-Facing Application"},
    "XSS_ATTEMPT":           {"id": "T1059.007", "name": "JavaScript XSS"},
    "DIRECTORY_TRAVERSAL":   {"id": "T1083",     "name": "File and Directory Discovery"},
    "PASSWORD_SPRAY":        {"id": "T1110.003", "name": "Password Spraying"},
    "CREDENTIAL_STUFFING":   {"id": "T1110.004", "name": "Credential Stuffing"},
    "PRIVILEGE_ESCALATION":  {"id": "T1548",     "name": "Abuse Elevation Control Mechanism"},
    "ACCOUNT_ENUMERATION":   {"id": "T1589.001", "name": "Account Enumeration"},
    "SUSPICIOUS_LOGIN":      {"id": "T1078",     "name": "Valid Accounts"},
}


# ── State management ──────────────────────────────────────────────────────────

def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_check": "1970-01-01T00:00:00", "alerted_event_hashes": []}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def event_hash(event: dict) -> str:
    """Stable fingerprint for an event so we don't double-alert."""
    return f"{event.get('type')}|{event.get('ip', '')}|{event.get('first_seen', event.get('timestamp', ''))}"


# ── Client lookup ─────────────────────────────────────────────────────────────

def load_clients() -> list:
    if not CLIENTS_FILE.exists():
        return []
    with open(CLIENTS_FILE) as f:
        return json.load(f).get("clients", [])


def get_client(client_id: str = "internal") -> dict:
    for c in load_clients():
        if c["client_id"] == client_id:
            return c
    return {"client_id": "internal", "name": "Internal", "email": JASON_EMAIL,
            "contact_name": "Jason", "industry": "Unknown"}


# ── Log parsing (mirrors security_agent.py) ───────────────────────────────────

def parse_log_since(since_ts: str) -> dict:
    """Parse flask_security.log, returning only events after since_ts."""
    events = {k: [] for k in ["login_failed", "login_success", "search",
                               "register", "xss_attempt", "directory_traversal",
                               "priv_esc_attempt", "account_enum"]}
    if not LOG_PATH.exists():
        return events

    pattern  = re.compile(r"(?P<timestamp>\S+)\s+(?P<level>\w+)\s+(?P<event>\w+)\s+(?P<fields>.*)")
    keywords = ["LOGIN", "SEARCH", "REGISTER", "XSS", "TRAVERSAL", "PRIV_ESC", "ACCOUNT_ENUM"]

    with open(LOG_PATH, "r") as f:
        for line in f:
            line = line.strip()
            if not any(kw in line for kw in keywords):
                continue
            m = pattern.match(line)
            if not m:
                continue
            ts = m.group("timestamp")
            if ts <= since_ts:
                continue   # already processed

            event_type = m.group("event").lower()
            fields     = m.group("fields")
            record     = {"timestamp": ts, "raw": line}
            for match in re.finditer(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)', fields):
                key, val = match.group(1), match.group(2).strip("'\"")
                record[key] = val

            if   event_type == "login_failed":        events["login_failed"].append(record)
            elif event_type == "login_success":       events["login_success"].append(record)
            elif event_type == "search":              events["search"].append(record)
            elif event_type == "register_success":    events["register"].append(record)
            elif event_type == "xss_attempt":         events["xss_attempt"].append(record)
            elif event_type == "directory_traversal": events["directory_traversal"].append(record)
            elif event_type == "priv_esc_attempt":    events["priv_esc_attempt"].append(record)
            elif event_type == "account_enum":        events["account_enum"].append(record)
    return events


# ── Threat detection ──────────────────────────────────────────────────────────

def detect_new_threats(events: dict) -> list:
    threats = []
    injection_re = re.compile(r"(?i)(' OR|' AND|--|'=|1=1|UNION|SELECT|DROP)")

    # Brute force - escalate to CRITICAL if it succeeded
    failed_by_user = defaultdict(list)
    for e in events["login_failed"]:
        failed_by_user[e.get("username", "unknown")].append(e)
    for uname, attempts in failed_by_user.items():
        if len(attempts) > BRUTE_THRESHOLD:
            success = any(e.get("username") == uname for e in events["login_success"])
            threats.append({
                "type":     "BRUTE_FORCE",
                "severity": "CRITICAL" if success else "HIGH",
                "username": uname,
                "ip":       attempts[0].get("ip", "unknown"),
                "detail":   f"{len(attempts)} failed attempts" + (" - ACCOUNT COMPROMISED" if success else ""),
                "first_seen": attempts[0]["timestamp"],
                "timestamp":  attempts[-1]["timestamp"],
                "mitre":    MITRE_MAP["BRUTE_FORCE"],
            })

    for e in events["search"]:
        query = e.get("query", e.get("extra", ""))
        if injection_re.search(query):
            threats.append({
                "type":     "SQL_INJECTION_ATTEMPT",
                "severity": "HIGH",
                "ip":       e.get("ip", "unknown"),
                "detail":   f"Payload: {query[:80]}",
                "timestamp": e["timestamp"],
                "mitre":    MITRE_MAP["SQL_INJECTION_ATTEMPT"],
            })

    for e in events["xss_attempt"]:
        threats.append({
            "type":     "XSS_ATTEMPT",
            "severity": "HIGH",
            "ip":       e.get("ip", "unknown"),
            "detail":   f"Payload: {e.get('payload', '')[:80]}",
            "timestamp": e["timestamp"],
            "mitre":    MITRE_MAP["XSS_ATTEMPT"],
        })

    for e in events["priv_esc_attempt"]:
        threats.append({
            "type":     "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "ip":       e.get("ip", "unknown"),
            "username": e.get("username", "unknown"),
            "detail":   "Attempted privilege escalation detected",
            "timestamp": e["timestamp"],
            "mitre":    MITRE_MAP["PRIVILEGE_ESCALATION"],
        })

    return threats


# ── Email templates ───────────────────────────────────────────────────────────

def _jason_alert_email(threats: list, client: dict) -> tuple[str, str]:
    """Internal alert: full technical detail for Jason."""
    critical = [t for t in threats if t["severity"] == "CRITICAL"]
    high     = [t for t in threats if t["severity"] == "HIGH"]

    subject = (
        f"[CRITICAL] Boundry.AI - {len(critical)} critical threat(s) | {client['name']}"
        if critical else
        f"[HIGH] Boundry.AI - {len(high)} threat(s) detected | {client['name']}"
    )

    lines = [
        f"BOUNDRY.AI - THREAT ALERT",
        f"Client:     {client['name']}",
        f"Time:       {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Threats:    {len(threats)} ({len(critical)} CRITICAL, {len(high)} HIGH)",
        "",
        "=" * 60,
        "THREAT DETAILS",
        "=" * 60,
    ]
    for t in threats:
        lines += [
            f"",
            f"[{t['severity']}] {t['type']}",
            f"  MITRE:    {t['mitre']['id']} - {t['mitre']['name']}",
            f"  Source IP: {t.get('ip', 'unknown')}",
            f"  Time:     {t.get('timestamp', 'unknown')}",
            f"  Detail:   {t.get('detail', '')}",
        ]

    lines += [
        "",
        "=" * 60,
        "ACTION REQUIRED" if critical else "ACTION RECOMMENDED",
        "=" * 60,
    ]
    if critical:
        lines += [
            "One or more CRITICAL threats require immediate attention.",
            "Review the Boundry.AI platform and generate a full incident report.",
        ]
    else:
        lines += [
            "HIGH severity threats detected. Review when possible.",
            "These will be included in the next monthly client report.",
        ]

    return subject, "\n".join(lines)


def _client_alert_email(client: dict, is_critical: bool) -> tuple[str, str]:
    """Client-facing email: calm, professional, non-technical."""
    name = client.get("contact_name", "there")
    biz  = client.get("name", "your business")

    subject = f"Security Notice - {biz} | Boundry.AI"

    if is_critical:
        body = f"""Hi {name},

Our monitoring systems have detected unusual activity affecting {biz}.

Our security team has been automatically notified and is actively investigating.
We are handling this on your behalf - you do not need to take any action at this time.

We will follow up with a full incident report once our investigation is complete.
If you have any concerns in the meantime, please reply to this email or call us directly.

You are protected.

- The Boundry.AI Security Team

---
Boundry.AI | Managed Cybersecurity Services
This is an automated alert from your 24/7 security monitoring system.
"""
    else:
        body = f"""Hi {name},

This is a routine security notification from your Boundry.AI monitoring system.

Our automated systems detected and logged suspicious activity targeting {biz}.
No action is required on your part - our team reviews all alerts and handles
them as part of your managed security service.

You will receive a full summary in your next monthly security report.

- The Boundry.AI Security Team

---
Boundry.AI | Managed Cybersecurity Services
"""

    return subject, body


# ── Email sender ──────────────────────────────────────────────────────────────

def send_email(to: str, subject: str, body: str, app_password: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"]    = JASON_EMAIL
        msg["To"]      = to
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(JASON_EMAIL, app_password)
            server.sendmail(JASON_EMAIL, to, msg.as_string())
        return True
    except Exception as e:
        print(f"  [EMAIL ERROR] {e}")
        return False


# ── Main monitor loop ─────────────────────────────────────────────────────────

def run_monitor(dry_run: bool = False, test_mode: bool = False):
    print(f"[Boundry.AI] Alert monitor started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    state   = load_state()
    clients = load_clients()
    active  = [c for c in clients if c.get("active")]

    if not active:
        print("[Boundry.AI] No active clients configured. Add clients to clients.json.")
        return

    # For now: single environment, assign to internal client
    # When you have real clients, each will have their own log feed
    client = get_client("internal")
    since  = state["last_check"]

    print(f"  Checking events since: {since}")
    events  = parse_log_since(since)
    threats = detect_new_threats(events)

    # Filter to only ones we haven't already alerted on
    alerted = set(state.get("alerted_event_hashes", []))
    new_threats = [t for t in threats if event_hash(t) not in alerted]

    if not new_threats:
        print("  No new threats detected.")
    else:
        critical = [t for t in new_threats if t["severity"] == "CRITICAL"]
        high     = [t for t in new_threats if t["severity"] == "HIGH"]
        print(f"  NEW THREATS: {len(new_threats)} ({len(critical)} CRITICAL, {len(high)} HIGH)")

        if not GMAIL_PASS and not dry_run:
            print("  [WARNING] GMAIL_APP_PASSWORD not set - emails skipped.")
            print("  Add to PowerShell profile: $env:GMAIL_APP_PASSWORD = 'your-app-password'")

        for t in new_threats:
            print(f"    [{t['severity']}] {t['type']} from {t.get('ip','?')} at {t.get('timestamp','?')}")

        if dry_run:
            print("  [DRY RUN] Emails not sent.")
        elif GMAIL_PASS:
            # Always email Jason
            subj, body = _jason_alert_email(new_threats, client)
            ok = send_email(JASON_EMAIL, subj, body, GMAIL_PASS)
            print(f"  Jason alert email: {'sent' if ok else 'FAILED'} -> {JASON_EMAIL}")

            # Email client only for CRITICAL (HIGH goes in monthly report)
            if critical and client["email"] != JASON_EMAIL:
                subj, body = _client_alert_email(client, is_critical=True)
                ok = send_email(client["email"], subj, body, GMAIL_PASS)
                print(f"  Client alert email: {'sent' if ok else 'FAILED'} -> {client['email']}")

        # Update state
        for t in new_threats:
            alerted.add(event_hash(t))

    # Update last_check time and save state
    state["last_check"] = datetime.now().isoformat()
    state["alerted_event_hashes"] = list(alerted)[-500:]  # keep last 500
    save_state(state)
    print(f"[Boundry.AI] Monitor complete.\n")


# ── Task Scheduler setup ──────────────────────────────────────────────────────

def register_task_scheduler():
    """Register alert_monitor.py to run every 15 minutes in Windows Task Scheduler."""
    import sys
    python   = sys.executable
    script   = str(Path(__file__).resolve())
    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{python}</Command>
      <Arguments>"{script}"</Arguments>
      <WorkingDirectory>{Path(script).parent}</WorkingDirectory>
    </Exec>
  </Actions>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
</Task>"""

    xml_path = Path(__file__).parent / "alert_task.xml"
    with open(xml_path, "w", encoding="utf-16") as f:
        f.write(task_xml)

    result = subprocess.run(
        ["schtasks", "/Create", "/TN", "BoundryAI-AlertMonitor",
         "/XML", str(xml_path), "/F"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("[Boundry.AI] Task Scheduler: BoundryAI-AlertMonitor registered (every 15 min)")
    else:
        print(f"[ERROR] Task Scheduler registration failed:\n{result.stderr}")
    xml_path.unlink(missing_ok=True)  # clean up temp file


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Boundry.AI Critical Alert Monitor")
    parser.add_argument("--dry-run",  action="store_true", help="Detect threats but don't send emails")
    parser.add_argument("--test",     action="store_true", help="Force-send a test alert email to Jason")
    parser.add_argument("--schedule", action="store_true", help="Register with Windows Task Scheduler (run once)")
    args = parser.parse_args()

    if args.schedule:
        register_task_scheduler()
    elif args.test:
        # Send a test email to confirm Gmail config works
        if not GMAIL_PASS:
            print("[ERROR] Set GMAIL_APP_PASSWORD environment variable first.")
        else:
            print("[Boundry.AI] Sending test alert to Jason...")
            ok = send_email(
                JASON_EMAIL,
                "[TEST] Boundry.AI Alert Monitor - Config Verified",
                f"Test alert sent at {datetime.now()}\n\nYour alert monitor is configured correctly.",
                GMAIL_PASS
            )
            print(f"Test email: {'sent OK' if ok else 'FAILED - check app password'}")
    else:
        run_monitor(dry_run=args.dry_run)
