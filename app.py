"""
Vulnerable Flask App — AppSec Learning Project
Deliberately insecure for security audit practice.
"""
import os
import sqlite3
import logging
from pathlib import Path

import bcrypt
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session

app = Flask(__name__)

# --- Session secret key (required for signing cookies) ---
# In production this must be a long random value from an env var — never hardcoded.
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-secret-change-in-prod")

# --- Security configuration (A05: Security Misconfiguration) ---
# On `main`, debug is OFF unless you explicitly opt in (local dev only).
# Phase 2: why DEBUG=True in production is dangerous (stack traces, Werkzeug PIN).
_debug = os.environ.get("FLASK_DEBUG", "").strip().lower() in ("1", "true", "yes")
app.config["DEBUG"] = _debug

DB_PATH = Path(__file__).parent / "app.db"

# --- Security logging (feeds into Splunk) ---
# Writes structured log lines to flask_security.log for SIEM ingestion.
LOG_PATH = Path(__file__).parent / "flask_security.log"
logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
security_log = logging.getLogger("security")


def init_db():
    """
    Create SQLite schema and seed fake users for the lab.

    Block job: give the search route predictable rows so SQLi / safe search demos
    behave the same every time. Never use real credentials here.
    Passwords are hashed with bcrypt — never stored in plaintext (A02 fix).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Only seed if the table is empty — avoids re-hashing on every restart
    cursor = conn.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        seed_users = [
            (1, "admin", "admin123"),
            (2, "alice", "alice456"),
            (3, "bob",   "bob789"),
        ]
        for uid, username, plaintext in seed_users:
            hashed = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt())
            conn.execute(
                "INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                (uid, username, hashed.decode()),
            )

    conn.commit()
    conn.close()


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
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

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
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()

            if existing:
                error = "Registration failed. Please try again."  # generic — no enumeration
                conn.close()
            else:
                # --- Hash and store ---
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, hashed.decode()),
                )
                conn.commit()
                conn.close()
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

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # SAFE: Parameterized query — ? is a placeholder; value passed separately as a tuple.
    # The database treats the value as DATA only, never as SQL syntax.
    sql = "SELECT * FROM users WHERE username LIKE ?"
    cursor = conn.execute(sql, (f"%{query}%",))
    results = [dict(row) for row in cursor.fetchall()]

    conn.close()

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


# --- Startup ---
if __name__ == "__main__":
    init_db()
    app.run(debug=_debug)
