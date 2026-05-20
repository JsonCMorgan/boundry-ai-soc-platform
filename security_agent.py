"""
Security Log Analyst Agent — Boundry.AI
Reads flask_security.log, detects threats, and generates a structured incident report.

Usage:
    python security_agent.py
    python security_agent.py --log path/to/custom.log
"""
import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import anthropic

LOG_PATH = Path(__file__).parent / "flask_security.log"
REPORTS_DIR = Path(__file__).parent / "docs" / "reports"
BRUTE_FORCE_THRESHOLD = 3


# --- Log Parsing ---

def parse_log(log_path: Path) -> dict:
    """
    Read the security log and extract structured event data.
    Returns counts and raw events grouped by type.
    """
    events = {
        "login_failed": [],
        "login_success": [],
        "search": [],
        "register": [],
    }

    pattern = re.compile(
        r"(?P<timestamp>\S+)\s+(?P<level>\w+)\s+(?P<event>\w+)\s+(?P<fields>.*)"
    )

    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if not any(kw in line for kw in ["LOGIN", "SEARCH", "REGISTER"]):
                continue
            m = pattern.match(line)
            if not m:
                continue
            event_type = m.group("event").lower()
            fields = m.group("fields")
            record = {"timestamp": m.group("timestamp"), "raw": line}

            # Extract key=value fields
            for match in re.finditer(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)', fields):
                key, val = match.group(1), match.group(2).strip("'\"")
                record[key] = val

            if event_type == "login_failed":
                events["login_failed"].append(record)
            elif event_type == "login_success":
                events["login_success"].append(record)
            elif event_type == "search":
                events["search"].append(record)
            elif event_type == "register_success":
                events["register"].append(record)

    return events


def detect_threats(events: dict) -> dict:
    """
    Run detection logic against parsed events.
    Returns structured threat findings.
    """
    threats = []

    # --- Brute force detection ---
    failed_by_user = defaultdict(list)
    for e in events["login_failed"]:
        username = e.get("username", "unknown")
        failed_by_user[username].append(e)

    for username, attempts in failed_by_user.items():
        if len(attempts) > BRUTE_FORCE_THRESHOLD:
            # Check if followed by a success — attacker may have succeeded
            success = any(
                e.get("username") == username for e in events["login_success"]
            )
            threats.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "username": username,
                "failed_attempts": len(attempts),
                "ip": attempts[0].get("ip", "unknown"),
                "succeeded": success,
                "first_seen": attempts[0]["timestamp"],
                "last_seen": attempts[-1]["timestamp"],
            })

    # --- SQL injection detection ---
    injection_pattern = re.compile(r"(?i)(' OR|' AND|--|'=|1=1|UNION|SELECT|DROP)")
    for e in events["search"]:
        query = e.get("query", "")
        if injection_pattern.search(query):
            threats.append({
                "type": "SQL_INJECTION_ATTEMPT",
                "severity": "HIGH",
                "username": e.get("username", "unknown"),
                "query": query,
                "ip": e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
            })

    return threats


# --- AI Report Generation ---

def generate_report(threats: list, events: dict) -> str:
    """
    Send threat findings to Claude and get a professional incident report back.
    """
    client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    summary = {
        "total_events": sum(len(v) for v in events.values()),
        "failed_logins": len(events["login_failed"]),
        "successful_logins": len(events["login_success"]),
        "searches": len(events["search"]),
        "threats_detected": len(threats),
        "threats": threats,
    }

    prompt = f"""You are a cybersecurity analyst writing an incident report for a client.

Analyze the following threat findings from a web application security log and write a
professional incident report. Be concise but thorough. Use plain language a business
owner can understand — not just technical jargon.

Log Summary:
{json.dumps(summary, indent=2)}

Write the report with these sections:
1. Executive Summary (2-3 sentences, plain English)
2. Findings (one paragraph per threat — what happened, what it means, severity)
3. Recommended Actions (bullet points, specific and actionable)
4. Risk Level (Overall: Critical/High/Medium/Low with one sentence justification)

Format as clean markdown."""

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    return message.content[0].text


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Boundry.AI Security Log Analyst")
    parser.add_argument("--log", type=Path, default=LOG_PATH, help="Path to log file")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI report, print raw findings only")
    args = parser.parse_args()

    if not args.log.exists():
        print(f"Error: Log file not found at {args.log}")
        sys.exit(1)

    print(f"Analyzing: {args.log}")
    events = parse_log(args.log)
    threats = detect_threats(events)

    print(f"Events parsed: {sum(len(v) for v in events.values())}")
    print(f"Threats detected: {len(threats)}")

    if args.no_ai or not os.environ.get("ANTHROPIC_API_KEY"):
        print("\n--- Raw Findings ---")
        for t in threats:
            print(json.dumps(t, indent=2))
        return

    print("Generating AI incident report...")
    report = generate_report(threats, events)

    # Save report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_path = REPORTS_DIR / f"incident_report_{timestamp}.md"
    report_path.write_text(report)

    print(f"\nReport saved: {report_path}")
    print("\n" + "="*60)
    print(report)


if __name__ == "__main__":
    main()
