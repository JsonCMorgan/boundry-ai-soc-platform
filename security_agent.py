"""
Security Log Analyst Agent — Boundry.AI
Reads flask_security.log, detects threats across all 9 attack categories,
and generates a structured incident report.

AI backend priority:
  1. Local Ollama  — 100% private, runs on your GPU (default)
  2. Anthropic Claude — cloud fallback if ANTHROPIC_API_KEY is set

Usage:
    python security_agent.py
    python security_agent.py --log path/to/custom.log
    python security_agent.py --no-ai

Environment variables:
    OLLAMA_BASE_URL   Base URL for Ollama API  (default: http://localhost:11434/v1)
    OLLAMA_MODEL      Model to use             (default: llama3.1:8b)
    ANTHROPIC_API_KEY Cloud fallback API key   (optional)
"""
import os
import re
import sys
import json
import argparse
import urllib.request
from pathlib import Path
from datetime import datetime
from collections import defaultdict

LOG_PATH    = Path(__file__).parent / "flask_security.log"
REPORTS_DIR = Path(__file__).parent / "docs" / "reports"
BRUTE_FORCE_THRESHOLD = 3

# MITRE ATT&CK mapping — all 9 threat categories
MITRE_MAP = {
    "BRUTE_FORCE":           {"id": "T1110",     "name": "Brute Force",                        "tactic": "Credential Access"},
    "SQL_INJECTION_ATTEMPT": {"id": "T1190",     "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
    "XSS_ATTEMPT":           {"id": "T1059.007", "name": "JavaScript (Cross-Site Scripting)",  "tactic": "Execution"},
    "DIRECTORY_TRAVERSAL":   {"id": "T1083",     "name": "File and Directory Discovery",       "tactic": "Discovery"},
    "PASSWORD_SPRAY":        {"id": "T1110.003", "name": "Password Spraying",                  "tactic": "Credential Access"},
    "CREDENTIAL_STUFFING":   {"id": "T1110.004", "name": "Credential Stuffing",                "tactic": "Credential Access"},
    "PRIVILEGE_ESCALATION":  {"id": "T1548",     "name": "Abuse Elevation Control Mechanism",  "tactic": "Privilege Escalation"},
    "ACCOUNT_ENUMERATION":   {"id": "T1589.001", "name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "SUSPICIOUS_LOGIN":      {"id": "T1078",     "name": "Valid Accounts",                     "tactic": "Defense Evasion"},
}


# ── Log Parsing ───────────────────────────────────────────────────────────────

def parse_log(log_path: Path) -> dict:
    """
    Read the security log and extract structured event data.
    Supports all 9 event types written by the Flask app.
    Returns a dict of event lists grouped by type.
    """
    events = {
        "login_failed":       [],
        "login_success":      [],
        "search":             [],
        "register":           [],
        "xss_attempt":        [],
        "directory_traversal":[],
        "priv_esc_attempt":   [],
        "account_enum":       [],
    }

    pattern = re.compile(
        r"(?P<timestamp>\S+)\s+(?P<level>\w+)\s+(?P<event>\w+)\s+(?P<fields>.*)"
    )

    keywords = ["LOGIN", "SEARCH", "REGISTER", "XSS", "TRAVERSAL", "PRIV_ESC", "ACCOUNT_ENUM"]

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not any(kw in line for kw in keywords):
                continue
            m = pattern.match(line)
            if not m:
                continue

            event_type = m.group("event").lower()
            fields     = m.group("fields")
            record     = {"timestamp": m.group("timestamp"), "raw": line}

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


# ── Threat Detection ──────────────────────────────────────────────────────────

def detect_threats(events: dict) -> list:
    """
    Run all 9 threat detectors against the parsed event data.
    Returns a list of threat dicts with MITRE ATT&CK mappings.
    """
    threats      = []
    injection_re = re.compile(r"(?i)(' OR|' AND|--|'=|1=1|UNION|SELECT|DROP)")

    # 1. Brute Force — T1110
    failed_by_user = defaultdict(list)
    for e in events["login_failed"]:
        failed_by_user[e.get("username", "unknown")].append(e)
    for uname, attempts in failed_by_user.items():
        if len(attempts) > BRUTE_FORCE_THRESHOLD:
            success = any(e.get("username") == uname for e in events["login_success"])
            threats.append({
                "type":            "BRUTE_FORCE",
                "severity":        "HIGH",
                "username":        uname,
                "failed_attempts": len(attempts),
                "ip":              attempts[0].get("ip", "unknown"),
                "succeeded":       success,
                "first_seen":      attempts[0]["timestamp"],
                "last_seen":       attempts[-1]["timestamp"],
                "mitre":           MITRE_MAP["BRUTE_FORCE"],
            })

    # 2. SQL Injection — T1190
    for e in events["search"]:
        query = e.get("query", e.get("extra", ""))
        if injection_re.search(query):
            threats.append({
                "type":      "SQL_INJECTION_ATTEMPT",
                "severity":  "HIGH",
                "username":  e.get("username", "unknown"),
                "query":     query,
                "ip":        e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
                "mitre":     MITRE_MAP["SQL_INJECTION_ATTEMPT"],
            })

    # 3. XSS — T1059.007
    for e in events["xss_attempt"]:
        threats.append({
            "type":      "XSS_ATTEMPT",
            "severity":  "HIGH",
            "username":  e.get("username", "unknown"),
            "payload":   e.get("payload", e.get("extra", "")),
            "ip":        e.get("ip", "unknown"),
            "timestamp": e["timestamp"],
            "mitre":     MITRE_MAP["XSS_ATTEMPT"],
        })

    # 4. Directory Traversal — T1083
    traversal_by_ip = defaultdict(list)
    for e in events["directory_traversal"]:
        traversal_by_ip[e.get("ip", "unknown")].append(e)
    for ip_addr, attempts in traversal_by_ip.items():
        threats.append({
            "type":       "DIRECTORY_TRAVERSAL",
            "severity":   "MEDIUM",
            "username":   attempts[0].get("username", "unknown"),
            "paths":      [e.get("path", e.get("extra", "")) for e in attempts],
            "attempts":   len(attempts),
            "ip":         ip_addr,
            "first_seen": attempts[0]["timestamp"],
            "last_seen":  attempts[-1]["timestamp"],
            "mitre":      MITRE_MAP["DIRECTORY_TRAVERSAL"],
        })

    # 5. Privilege Escalation — T1548
    priv_by_user = defaultdict(list)
    for e in events["priv_esc_attempt"]:
        priv_by_user[e.get("username", "unknown")].append(e)
    for uname, attempts in priv_by_user.items():
        threats.append({
            "type":      "PRIVILEGE_ESCALATION",
            "severity":  "HIGH",
            "username":  uname,
            "routes":    [e.get("route", e.get("extra", "")) for e in attempts],
            "attempts":  len(attempts),
            "ip":        attempts[0].get("ip", "unknown"),
            "timestamp": attempts[0]["timestamp"],
            "mitre":     MITRE_MAP["PRIVILEGE_ESCALATION"],
        })

    # 6. Account Enumeration — T1589.001
    enum_by_ip = defaultdict(list)
    for e in events["account_enum"]:
        enum_by_ip[e.get("ip", "unknown")].append(e)
    for ip_addr, attempts in enum_by_ip.items():
        if len(attempts) >= 4:
            threats.append({
                "type":             "ACCOUNT_ENUMERATION",
                "severity":         "MEDIUM",
                "ip":               ip_addr,
                "usernames_probed": len(attempts),
                "first_seen":       attempts[0]["timestamp"],
                "last_seen":        attempts[-1]["timestamp"],
                "mitre":            MITRE_MAP["ACCOUNT_ENUMERATION"],
            })

    # 7. Password Spray — T1110.003
    spray_by_ip = defaultdict(set)
    for e in events["login_failed"]:
        if "sprayed_password=" in e.get("extra", ""):
            spray_by_ip[e.get("ip", "unknown")].add(e.get("username", "unknown"))
    for ip_addr, accounts in spray_by_ip.items():
        if len(accounts) >= 4:
            threats.append({
                "type":              "PASSWORD_SPRAY",
                "severity":          "HIGH",
                "ip":                ip_addr,
                "accounts_targeted": len(accounts),
                "mitre":             MITRE_MAP["PASSWORD_SPRAY"],
            })

    # 8. Credential Stuffing — T1110.004
    stuff_by_ip = defaultdict(set)
    for e in events["login_failed"]:
        if "sprayed_password=" not in e.get("extra", ""):
            stuff_by_ip[e.get("ip", "unknown")].add(e.get("username", "unknown"))
    for ip_addr, accounts in stuff_by_ip.items():
        if len(accounts) >= 4:
            successes = [s for s in events["login_success"] if s.get("ip") == ip_addr]
            threats.append({
                "type":              "CREDENTIAL_STUFFING",
                "severity":          "CRITICAL" if successes else "HIGH",
                "ip":                ip_addr,
                "accounts_targeted": len(accounts),
                "succeeded":         bool(successes),
                "mitre":             MITRE_MAP["CREDENTIAL_STUFFING"],
            })

    # 9. Suspicious Login — T1078
    for e in events["login_success"]:
        extra = e.get("extra", "")
        if "unusual_hour=true" in extra or "new_ip=true" in extra:
            threats.append({
                "type":      "SUSPICIOUS_LOGIN",
                "severity":  "MEDIUM",
                "username":  e.get("username", "unknown"),
                "ip":        e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
                "mitre":     MITRE_MAP["SUSPICIOUS_LOGIN"],
            })

    return threats


# ── AI Report Generation ──────────────────────────────────────────────────────

def generate_report(threats: list, events: dict) -> str:
    """
    Generate a professional incident report using AI.
    Tries local Ollama first (private), falls back to Anthropic Claude.
    Raises RuntimeError if both backends are unavailable.
    """
    summary = {
        "total_events":       sum(len(v) for v in events.values()),
        "failed_logins":      len(events["login_failed"]),
        "successful_logins":  len(events["login_success"]),
        "searches":           len(events["search"]),
        "xss_attempts":       len(events["xss_attempt"]),
        "directory_traversals":len(events["directory_traversal"]),
        "priv_esc_attempts":  len(events["priv_esc_attempt"]),
        "account_enum_events":len(events["account_enum"]),
        "threats_detected":   len(threats),
        "threats":            threats,
    }

    prompt = f"""You are a senior SOC (Security Operations Centre) analyst at Boundry.AI \
writing a formal incident report for a client. Your audience is both the business owner \
(plain English) and the IT team (technical detail).

Analyse the following threat data and produce a professional incident report.

Incident Data:
{json.dumps(summary, indent=2)}

Write the report using exactly these sections:

## Executive Summary
2-3 sentences. What happened, the business impact, and the bottom line.

## Attack Timeline
Chronological bullet points of the attack sequence from first event to last.

## Kill Chain Analysis
If multiple threats share the same attacker IP and form a logical progression \
(e.g. enumeration → credential access → takeover → privilege escalation), identify \
this as an APT campaign and describe the full kill chain. Otherwise skip this section.

## Threat Analysis
One sub-section per threat. Include: MITRE ATT&CK technique (ID + name), what the \
attacker did in plain English, whether the attack succeeded, severity, and business impact.

## Indicators of Compromise (IOCs)
Markdown table: Type | Value | Context
Include all attacker IPs, targeted usernames, and malicious payloads.

## Recommended Actions
Prioritised bullet points split into:
- **Immediate (0-24 hours)**
- **Short-term (1-7 days)**
- **Long-term hardening**

## Overall Risk Level
Critical / High / Medium / Low — one sentence justification.

Format as clean markdown. Use tables where appropriate."""

    # --- 1. Local Ollama (100% private, zero cloud) ---
    ollama_base  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    ollama_model = os.environ.get("OLLAMA_MODEL",    "llama3.1:8b")
    try:
        payload = json.dumps({
            "model":       ollama_model,
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  2048,
            "temperature": 0.3,
        }).encode()
        req = urllib.request.Request(
            f"{ollama_base}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            text = data["choices"][0]["message"]["content"].strip()
            print(f"[AI] Report generated via local Ollama ({ollama_model})")
            return text
    except Exception as exc:
        print(f"[WARN] Ollama unavailable ({exc}) — trying Anthropic fallback...")

    # --- 2. Anthropic Claude (cloud fallback) ---
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        try:
            import anthropic
            client  = anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            print("[AI] Report generated via Anthropic Claude (cloud fallback)")
            return message.content[0].text
        except Exception as exc:
            print(f"[ERROR] Anthropic also failed: {exc}")

    raise RuntimeError(
        "No AI backend available. "
        "Ensure Ollama is running (http://localhost:11434) "
        "or set the ANTHROPIC_API_KEY environment variable."
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Boundry.AI Security Log Analyst — detects threats and generates incident reports"
    )
    parser.add_argument(
        "--log",   type=Path, default=LOG_PATH,
        help="Path to the Flask security log file (default: flask_security.log)"
    )
    parser.add_argument(
        "--no-ai", action="store_true",
        help="Skip AI report generation and print raw threat findings only"
    )
    args = parser.parse_args()

    if not args.log.exists():
        print(f"[ERROR] Log file not found: {args.log}")
        sys.exit(1)

    print(f"[*] Analysing: {args.log}")
    events  = parse_log(args.log)
    threats = detect_threats(events)

    total_events = sum(len(v) for v in events.values())
    print(f"[*] Events parsed:    {total_events}")
    print(f"[*] Threats detected: {len(threats)}")

    if not threats:
        print("[*] No threats found in log — system is clean.")
        return

    # Print threat summary
    print()
    for t in threats:
        mitre = t.get("mitre", {})
        print(f"  [{t['severity']:8}] {t['type']:<25} — {mitre.get('id','')} {mitre.get('name','')}")
    print()

    if args.no_ai:
        print("--- Raw Findings ---")
        for t in threats:
            print(json.dumps(t, indent=2))
        return

    print("[*] Generating AI incident report...")
    try:
        report = generate_report(threats, events)
    except RuntimeError as e:
        print(f"[ERROR] {e}")
        print("\n--- Raw Findings (no AI available) ---")
        for t in threats:
            print(json.dumps(t, indent=2))
        return

    # Save report to docs/reports/
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_path = REPORTS_DIR / f"incident_report_{timestamp}.md"
    report_path.write_text(report, encoding="utf-8")

    print(f"[+] Report saved: {report_path}")
    print("\n" + "=" * 60)
    print(report)


if __name__ == "__main__":
    main()
