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
from functools import wraps
from markupsafe import Markup
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash, jsonify
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
    # Migration: add role column to existing users tables.
    if DATABASE_URL:
        db_run("ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'client'")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(users)")]
        if "role" not in existing_cols:
            db_run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'client'")

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
    # Migration: add event_count to existing reports tables that pre-date this column.
    # PostgreSQL supports "ADD COLUMN IF NOT EXISTS"; SQLite needs a PRAGMA check.
    if DATABASE_URL:
        db_run("ALTER TABLE reports ADD COLUMN IF NOT EXISTS event_count INTEGER NOT NULL DEFAULT 0")
    else:
        existing_cols = [r["name"] for r in db_fetchall("PRAGMA table_info(reports)")]
        if "event_count" not in existing_cols:
            db_run("ALTER TABLE reports ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0")

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
            extra      TEXT NOT NULL DEFAULT ''
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
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                db_run(
                    f"INSERT INTO users (username, password) VALUES ({PH}, {PH})",
                    (username, hashed.decode()),
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
    report_list = db_fetchall(
        "SELECT id, created_at, threat_count, event_count FROM reports ORDER BY id DESC"
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
        f"SELECT id, created_at, threat_count, event_count, content FROM reports WHERE id = {PH}",
        (report_id,),
    )

    if not row:
        abort(404)

    html_content = Markup(markdown.markdown(row["content"], extensions=["tables"]))
    return render_template(
        "report_detail.html",
        content=html_content,
        report_id=row["id"],
        created_at=row["created_at"],
        threat_count=row["threat_count"],
        event_count=row["event_count"],
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
        "SELECT id, created_at, threat_count, event_count FROM reports ORDER BY id DESC"
    )
    pending_events = db_fetchone("SELECT COUNT(*) AS cnt FROM security_events")
    pending_count  = pending_events["cnt"] if pending_events else 0

    # Summary stats for the header bar
    total_clients = len([c for c in clients if c["role"] == "client"])
    total_reports = len(all_reports)
    total_threats = sum(r["threat_count"] for r in all_reports)
    total_events  = sum(r["event_count"]  for r in all_reports)

    return render_template(
        "control_room.html",
        clients=clients,
        reports=all_reports,
        pending_count=pending_count,
        total_clients=total_clients,
        total_reports=total_reports,
        total_threats=total_threats,
        total_events=total_events,
    )


# --- ROUTE 5: Attack Simulation (Boundry.AI demo / cron helper) ---
@app.route("/simulate-attack", methods=["POST"])
@login_required
def simulate_attack():
    """
    Write realistic fake attack events to the security log so the /run-agent
    endpoint has data to analyse.  Used by the Railway hourly cron job to keep
    the demo dashboard populated with fresh reports.

    Simulates:
      - 5 failed login attempts for "admin" from a known-bad IP
      - 1 successful login (attacker cracked the account)
      - 2 SQL injection attempts via the search route
    """
    attacker_ip = "203.0.113.42"   # TEST-NET-3 — documentation-only range, never real

    # Brute force sequence
    for _ in range(5):
        security_log.warning(f"LOGIN_FAILED username=admin ip={attacker_ip}")
        db_run(
            f"INSERT INTO security_events (event_type, username, ip, extra) VALUES ({PH},{PH},{PH},{PH})",
            ("LOGIN_FAILED", "admin", attacker_ip, ""),
        )

    # Simulated success (account compromise)
    security_log.info(f"LOGIN_SUCCESS username=admin ip={attacker_ip}")
    db_run(
        f"INSERT INTO security_events (event_type, username, ip, extra) VALUES ({PH},{PH},{PH},{PH})",
        ("LOGIN_SUCCESS", "admin", attacker_ip, ""),
    )

    # SQL injection attempts via search
    for payload in ["' OR '1'='1", "' UNION SELECT username, password FROM users--"]:
        security_log.info(f"SEARCH username=admin query={payload!r} ip={attacker_ip}")
        db_run(
            f"INSERT INTO security_events (event_type, username, ip, extra) VALUES ({PH},{PH},{PH},{PH})",
            ("SEARCH", "admin", attacker_ip, payload),
        )

    # Browser form POST → redirect back to dashboard with a status message.
    # API / cron job → returns JSON (detected by missing text/html Accept header).
    if "text/html" in request.accept_mimetypes:
        flash("⚡ Attack simulation complete — 8 events written. Now click Run Agent.", "info")
        return redirect(url_for("reports"))
    return jsonify(status="ok", events_generated=8)


# --- ROUTE 6: Agent Trigger (Boundry.AI demo / cron helper) ---
@app.route("/run-agent", methods=["POST"])
@login_required
def run_agent():
    """
    Read recent log events, run threat detection, and (if ANTHROPIC_API_KEY is
    set) call the Claude API to generate a plain-English incident report, then
    save it to the reports DB table.

    Returns JSON so Railway cron jobs can confirm success via exit code / response.
    """
    import json as _json

    log_path = Path(os.environ.get("LOG_FILE", "")) if os.environ.get("LOG_FILE") else None

    # Inline the parse/detect logic (mirrors security_agent.py) so this route
    # works without the agent script being importable in all deployment configs.
    from collections import defaultdict

    events = {
        "login_failed": [],
        "login_success": [],
        "search": [],
        "register": [],
    }

    # --- Source 1: log file (local dev with LOG_FILE set) ---
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
                fields = m.group("fields")
                record = {"timestamp": m.group("timestamp"), "raw": line}
                for match in _re.finditer(r'(\w+)=("[^"]*"|\'[^\']*\'|\S+)', fields):
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

    # --- Source 2: DB security_events table (Railway / production path) ---
    # /simulate-attack writes here so the agent always has data even without LOG_FILE.
    # Clear the table after reading so the next run starts fresh.
    db_rows = db_fetchall("SELECT * FROM security_events ORDER BY id ASC")
    for row in db_rows:
        record = {
            "timestamp": str(row["created_at"]),
            "username":  row["username"],
            "ip":        row["ip"],
        }
        etype = row["event_type"].upper()
        if etype == "LOGIN_FAILED":
            events["login_failed"].append(record)
        elif etype == "LOGIN_SUCCESS":
            events["login_success"].append(record)
        elif etype == "SEARCH":
            record["query"] = row["extra"]
            events["search"].append(record)
        elif etype == "REGISTER_SUCCESS":
            events["register"].append(record)
    if db_rows:
        db_run("DELETE FROM security_events")

    # --- Threat detection ---
    BRUTE_THRESHOLD = 3
    injection_re = re.compile(r"(?i)(' OR|' AND|--|'=|1=1|UNION|SELECT|DROP)")
    threats = []

    failed_by_user = defaultdict(list)
    for e in events["login_failed"]:
        failed_by_user[e.get("username", "unknown")].append(e)

    for username, attempts in failed_by_user.items():
        if len(attempts) > BRUTE_THRESHOLD:
            success = any(e.get("username") == username for e in events["login_success"])
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

    for e in events["search"]:
        query = e.get("query", "")
        if injection_re.search(query):
            threats.append({
                "type": "SQL_INJECTION_ATTEMPT",
                "severity": "HIGH",
                "username": e.get("username", "unknown"),
                "query": query,
                "ip": e.get("ip", "unknown"),
                "timestamp": e["timestamp"],
            })

    threat_count = len(threats)
    event_count  = sum(len(v) for v in events.values())  # total raw events analysed

    # --- Generate and save report ---
    report_id = None
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if threat_count == 0 and not db_rows and not log_path:
        # No events from any source — nothing to analyse yet.
        if "text/html" in request.accept_mimetypes:
            flash("⚠️ No events found. Click 'Simulate Attack' first, then run the agent.", "warning")
            return redirect(url_for("reports"))
        return jsonify(status="ok", threats_found=0, report_id=None,
                       message="No events found. Run Simulate Attack first.")

    if api_key and threat_count > 0:
        try:
            import anthropic as _anthropic
            client = _anthropic.Anthropic(api_key=api_key)
            summary = {
                "total_events": sum(len(v) for v in events.values()),
                "failed_logins": len(events["login_failed"]),
                "successful_logins": len(events["login_success"]),
                "searches": len(events["search"]),
                "threats_detected": threat_count,
                "threats": threats,
            }
            prompt = (
                "You are a cybersecurity analyst writing an incident report for a client.\n\n"
                "Analyze the following threat findings from a web application security log and write a "
                "professional incident report. Be concise but thorough. Use plain language a business "
                "owner can understand — not just technical jargon.\n\n"
                f"Log Summary:\n{_json.dumps(summary, indent=2)}\n\n"
                "Write the report with these sections:\n"
                "1. Executive Summary (2-3 sentences, plain English)\n"
                "2. Findings (one paragraph per threat — what happened, what it means, severity)\n"
                "3. Recommended Actions (bullet points, specific and actionable)\n"
                "4. Risk Level (Overall: Critical/High/Medium/Low with one sentence justification)\n\n"
                "Format as clean markdown."
            )
            message = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            content = message.content[0].text
        except Exception as exc:
            content = f"# Report Generation Error\n\nAI report could not be generated: {exc}"
    else:
        # Placeholder report when no API key is set.
        # Still shows the full event breakdown so clients can account for every event.
        failed_ct  = len(events["login_failed"])
        success_ct = len(events["login_success"])
        search_ct  = len(events["search"])

        lines = [
            "# Incident Report\n",
            "---\n",
            "## Events Analysed\n",
            f"| Event type | Count |",
            f"|---|---|",
            f"| Failed login attempts | {failed_ct} |",
            f"| Successful logins | {success_ct} |",
            f"| Search / query events | {search_ct} |",
            f"| **Total** | **{event_count}** |",
            "",
        ]

        if threat_count > 0:
            lines += [
                f"## Threats Detected: {threat_count}\n",
            ]
            for t in threats:
                if t["type"] == "BRUTE_FORCE":
                    outcome = "✅ Account compromised" if t.get("succeeded") else "🛡 Access denied"
                    lines.append(
                        f"### 🔴 Brute Force Attack — {t['severity']}\n"
                        f"- **Target account:** {t['username']}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Failed attempts:** {t['failed_attempts']}\n"
                        f"- **Outcome:** {outcome}\n"
                        f"- **First seen:** {t['first_seen']} | **Last seen:** {t['last_seen']}\n"
                    )
                elif t["type"] == "SQL_INJECTION_ATTEMPT":
                    lines.append(
                        f"### 🔴 SQL Injection Attempt — {t['severity']}\n"
                        f"- **User:** {t.get('username','unknown')}\n"
                        f"- **Attacker IP:** {t['ip']}\n"
                        f"- **Payload:** `{t.get('query','')}`\n"
                        f"- **Timestamp:** {t.get('timestamp','')}\n"
                    )
            lines += [
                "---\n",
                "> **Note:** Add `ANTHROPIC_API_KEY` as a Railway environment variable "
                "to replace this report with a full AI-generated narrative."
            ]
        else:
            lines += [
                "## No Threats Detected\n",
                "The agent found no brute-force or injection patterns in the current events.\n",
            ]

        content = "\n".join(lines)

    # Store in DB
    if DATABASE_URL:
        ts_expr = "NOW()"
    else:
        ts_expr = "datetime('now')"

    db_run(
        f"INSERT INTO reports (created_at, threat_count, event_count, content) VALUES ({ts_expr}, {PH}, {PH}, {PH})",
        (threat_count, event_count, content),
    )
    # Retrieve the new row id
    row = db_fetchone("SELECT id FROM reports ORDER BY id DESC LIMIT 1")
    report_id = row["id"] if row else None

    security_log.info(
        f"AGENT_RUN threats_found={threat_count} report_id={report_id} "
        f"user={session.get('username')} ip={request.remote_addr}"
    )

    # Browser form POST → redirect to dashboard with a flash message.
    # API / cron job → return JSON.
    if "text/html" in request.accept_mimetypes:
        if report_id:
            flash(f"🤖 Agent complete — {event_count} events analysed, {threat_count} threat(s) detected. Report #{report_id} saved.", "success")
        else:
            flash("🤖 Agent ran but found no threats in the current events.", "info")
        return redirect(url_for("reports"))
    return jsonify(status="ok", threats_found=threat_count, report_id=report_id)


# --- Startup ---
# init_db() must run at module level so gunicorn (production) initialises
# the database on import, not just when running via `python app.py`.
init_db()

if __name__ == "__main__":
    app.run(debug=_debug)
