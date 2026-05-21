"""
Vulnerable Flask App — AppSec Learning Project
Deliberately insecure for security audit practice.
"""
import os
import sqlite3
import logging
from pathlib import Path

import markdown
import bcrypt
from functools import wraps
from markupsafe import Markup
from flask import Flask, render_template, request, redirect, url_for, session, abort
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
            password TEXT NOT NULL
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


# --- Auth decorator (bouncer) ---
def login_required(f):
    """Redirect to login if the user has no active session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
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
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Look up user by username
        row = db_fetchone(f"SELECT * FROM users WHERE username = {PH}", (username,))

        # Verify password against stored hash
        if row and bcrypt.checkpw(password.encode(), row["password"].encode()):
            session["username"] = username   # session is signed — safe to trust
            security_log.info(f"LOGIN_SUCCESS username={username} ip={request.remote_addr}")
            return redirect(url_for("index"))
        else:
            security_log.warning(f"LOGIN_FAILED username={username} ip={request.remote_addr}")
            error = "Invalid username or password."  # generic — don't hint which field failed

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for("login"))


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
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
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
    List all generated incident reports, newest first.
    Only shows incident_report_*.md files — never the SAMPLE or pricing docs.
    Protected by login_required: clients log in to view their reports.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_files = sorted(REPORTS_DIR.glob("incident_report_*.md"), reverse=True)
    report_list = [
        {
            "filename": f.name,
            "display": f.stem.replace("incident_report_", "").replace("_", " "),
        }
        for f in report_files
    ]
    return render_template("reports.html", reports=report_list)


@app.route("/reports/<filename>")
@login_required
def report_detail(filename):
    """
    Render a single incident report as HTML.

    Security: resolves the full path and confirms it stays inside REPORTS_DIR
    before reading — prevents path traversal attacks (e.g. ../../etc/passwd).
    """
    safe_path = (REPORTS_DIR / filename).resolve()

    # Path traversal protection: reject anything that escapes the reports folder
    if not str(safe_path).startswith(str(REPORTS_DIR.resolve())):
        abort(404)

    # Only serve .md files that actually exist
    if not safe_path.exists() or safe_path.suffix != ".md":
        abort(404)

    raw = safe_path.read_text()
    html_content = Markup(markdown.markdown(raw))
    return render_template("report_detail.html", content=html_content, filename=filename)


# --- Startup ---
# init_db() must run at module level so gunicorn (production) initialises
# the database on import, not just when running via `python app.py`.
init_db()

if __name__ == "__main__":
    app.run(debug=_debug)
