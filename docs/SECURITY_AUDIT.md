# Security Audit Report — Vulnerable Flask App

**Author:** Jason Morgan
**Date:** May 2026
**Branch tested:** `vulnerable` compared against `main`
**Environment:** Localhost only — http://127.0.0.1:5000

---

## Executive Summary

This report documents a security audit of a deliberately vulnerable Flask web application built for AppSec learning. The audit identified seven vulnerabilities across the application — SQL Injection, Cross-Site Scripting (XSS), Security Misconfiguration, Cryptographic Failures, and Broken Access Control — all of which were traced from the point of user input through to their impact and verified on the patched `main` branch. A login system with bcrypt password hashing, signed session cookies, and route-level access control was designed and implemented as part of the remediation phase. The goal of this audit is to demonstrate practical understanding of OWASP Top 10 risks, how they appear in real code, and what it takes to fix them before they reach production.

I like to think of this application as a building — SQL Injection is a backdoor that lets someone rewrite the guest list, XSS is a stranger slipping a note through the mail slot that tricks other tenants into handing over their keys, and leaving debug mode on is like taping the building's blueprints to the front door. This audit is about finding those doors before someone else does.

---

## Scope

- **Application:** Vulnerable Flask App (localhost only)
- **Branch tested:** `vulnerable` (exploitable patterns) compared against `main` (patched baseline)
- **Testing environment:** Local machine, http://127.0.0.1:5000 — no external network exposure
- **What was tested:** All routes (`/`, `/login`, `/logout`, `/search`, `/greeting`), templates, session management, and application configuration
- **What was not tested:** File uploads, external infrastructure, password reset flows, or multi-user privilege escalation — none of which exist in this application
- **Testing method:** Manual code review and hands-on exploitation using browser-based payloads

---

## Findings Summary

| # | Title | OWASP Category | Location | Severity | Status |
|---|-------|---------------|----------|----------|--------|
| 1 | SQL Injection via string concatenation | A03 — Injection | `/search` route, `app.py` line 68 | High | Fixed on `main` |
| 2 | Reflected XSS via Jinja2 `\|safe` filter | A03 — Injection | `/greeting` route, `greeting.html` line 16 | High | Fixed on `main` |
| 3 | Debug mode hardcoded on | A05 — Security Misconfiguration | `app.py` line 12 | Critical | Fixed on `main` |
| 4 | Plaintext passwords exposed in UI | A02 — Cryptographic Failures | `search.html`, `init_db()` | Medium | Not fixed — intentional lab design |
| 5 | SELECT * exposes password column to template | A02 — Cryptographic Failures | `/search` route, `app.py` line 68 | Medium | Not fixed — intentional lab design |
| 6 | No authentication on protected routes | A01 — Broken Access Control | `/search`, `/greeting` routes | High | Fixed on `main` |
| 7 | No password hashing on stored credentials | A02 — Cryptographic Failures | `init_db()`, `app.py` | High | Fixed on `main` |

---

## Finding Details

### Finding 1 — SQL Injection via String Concatenation

**OWASP:** A03 — Injection
**Severity:** High
**Location:** `/search` route, `app.py` line 68

**Description:**
The search route builds its SQL query by concatenating user input directly into the query string using an f-string. This allows an attacker to inject SQL syntax that changes the structure and behavior of the query entirely. I like to think of it like smuggling a nail file inside a cake — the input looks innocent on the outside, but hidden inside is exactly what the attacker needs to break out of the boundaries the application was supposed to enforce.

**Impact:**
An attacker can dump every record in the database — including usernames and passwords — without any valid credentials. In a real production application this could expose every user account in the system.

**Proof of Concept:**
Entering `' OR '1'='1' --` into the search box returned all users and passwords in the database. The injected syntax forced the query to evaluate as always true, bypassing the intended search filter entirely.

**Remediation:**
Replaced f-string concatenation with a parameterized query using a `?` placeholder. The database now treats user input as data only — never as SQL syntax.

---

### Finding 2 — Reflected XSS via Jinja2 `|safe` Filter

**OWASP:** A03 — Injection
**Severity:** High
**Location:** `/greeting` route, `greeting.html` line 16

**Description:**
The greeting template uses Jinja2's `|safe` filter on user-supplied input from the URL, which disables automatic HTML escaping. This allows an attacker to inject raw HTML or JavaScript that executes directly in the victim's browser. I like to think of it like a mailbox that can be opened by any key — anyone can drop anything inside, including fraudulent mail designed to trick the recipient into handing over their personal information. The application is the mailbox, and the victim is the tenant who trusts whatever comes out of it.

**Impact:**
An attacker can craft a malicious URL and trick another user into clicking it. Once clicked, the injected script runs in the victim's browser — potentially stealing session cookies, redirecting to fake login pages, or performing actions on the victim's behalf without their knowledge.

**Proof of Concept:**
Entering `<script>alert('XSS')</script>` as the `name` parameter triggered a JavaScript popup in the browser, confirming the script was executed rather than displayed as plain text.

**Remediation:**
Removed the `|safe` filter from the greeting template. Jinja2's default auto-escaping now converts any HTML characters in user input into plain text — the browser displays them but never executes them.

---

### Finding 3 — Debug Mode Hardcoded On

**OWASP:** A05 — Security Misconfiguration
**Severity:** Critical
**Location:** `app.py` line 12

**Description:**
Debug mode was hardcoded as `DEBUG = True` directly in the application code. This means every time the application runs, the Flask debugger is active regardless of the environment. I like to think of it like taping the blueprints of your building to the front door — anyone who walks by can see exactly how everything is built, where the weak points are, and how to get inside.

**Impact:**
When an error occurs, Flask exposes a full interactive Python console in the browser along with a complete stack trace showing internal file paths, line numbers, and source code. An attacker who can trigger an error gains the ability to execute arbitrary Python code on the server directly from their browser.

**Proof of Concept:**
Submitting a malformed SQL payload to the `/search` route triggered an error page that exposed the full stack trace, internal file structure, and an active Werkzeug debugger PIN in the terminal.

**Remediation:**
Replaced `DEBUG = True` with an environment variable check. Debug mode now only activates when `FLASK_DEBUG` is explicitly set — it is off by default in all environments.

---

### Finding 4 — Plaintext Passwords Exposed in UI

**OWASP:** A02 — Cryptographic Failures
**Severity:** Medium
**Location:** `search.html`, `init_db()` in `app.py`

**Description:**
Passwords are stored as plaintext in the database and displayed directly in the search results table in the browser. There is no hashing, masking, or access control preventing any user from seeing every other user's password. I like to think of it like a filing cabinet in the middle of a lobby — unlocked, with everyone's personal information sitting right on top, visible to anyone who walks through the door.

**Impact:**
Any user with access to the search page can view every password in the database instantly — no exploitation required. In a real production application this would result in full account compromise for every user in the system. If users reuse passwords across other services, the damage extends far beyond this application.

**Proof of Concept:**
Navigating to `/search` without any input returned all three user records including plaintext passwords displayed in a browser table — no special payload required.

**Remediation:**
Passwords should be hashed using a strong one-way algorithm such as bcrypt before being stored. The password column should also be removed entirely from search results — there is no legitimate reason to display passwords in a UI under any circumstances.

---

### Finding 5 — SELECT * Exposes Password Column to Template

**OWASP:** A02 — Cryptographic Failures
**Severity:** Medium
**Location:** `/search` route, `app.py` line 68

**Description:**
The search query uses `SELECT *` which returns all columns from the users table — including the password field — and passes them to the template. Even though the current template may not display the password column, the data is in memory and available to the template engine. This violates the principle of least privilege: only request what you actually need.

**Impact:**
If the template is ever modified to display additional columns, or if a developer adds debug output, passwords could be rendered directly in the browser with no additional vulnerability required. The risk is one template change away from full credential exposure.

**Remediation:**
Replace `SELECT *` with `SELECT id, username` — never pull columns that don't need to be used. Sensitive fields should be excluded at the query level, not relied on being hidden at the template level.

---

### Finding 6 — No Authentication on Protected Routes

**OWASP:** A01 — Broken Access Control
**Severity:** High
**Location:** `/search`, `/greeting` routes, `app.py`

**Description:**
The `/search` and `/greeting` routes were accessible to any user without requiring authentication. There was no session check or access control mechanism in place — anyone who knew the URL could reach the routes directly, bypassing any intended login requirement. Think of it like a building where the lobby has a security desk but every internal door is left wide open.

**Impact:**
Unauthenticated users could access the search functionality and retrieve all usernames from the database. In a real application this could expose sensitive user data to anyone with a browser.

**Proof of Concept:**
Navigating directly to `/search` without an active session returned a 200 response with full search results — no login required.

**Remediation:**
A `login_required` decorator was implemented and applied to all protected routes. It checks for an active session on every request and redirects unauthenticated users to `/login` with a 302 response. Regression tests verify this behavior cannot be silently broken.

---

### Finding 7 — No Password Hashing on Stored Credentials

**OWASP:** A02 — Cryptographic Failures
**Severity:** High
**Location:** `init_db()`, `app.py`

**Description:**
Seed user passwords were stored as plaintext strings in the database. Any database dump, backup leak, or SQL injection attack would expose all credentials immediately with no additional effort required. There was no hashing, salting, or any cryptographic protection applied at the storage layer.

**Impact:**
Full credential compromise on database exposure. Plaintext passwords are immediately usable — no cracking required. If users reuse those passwords elsewhere, the damage extends to other services.

**Proof of Concept:**
Direct database query returned `admin123`, `alice456`, and `bob789` in plaintext.

**Remediation:**
Passwords are now hashed using bcrypt with per-password salts before storage. At login, bcrypt compares the hash of the submitted password against the stored hash — the plaintext password never exists in the database. A regression test verifies that stored passwords do not match their plaintext equivalents.

---

## Recommendations

**1. Never ship with default or development settings in production.**
Security configuration should be reviewed before every deployment. Debug mode, verbose error messages, and development tools should be explicitly disabled by default and only enabled through environment variables when needed. If a setting wasn't deliberately chosen for the environment it's running in, it shouldn't be there.

**2. Treat all user input as untrusted by default.**
Every place where user input enters the application — URLs, forms, query parameters — should be validated, sanitized, and handled in a way that prevents it from changing the behavior of the system. Parameterized queries for SQL and auto-escaping for templates should be the default pattern, not an afterthought.

**3. Make password hashing mandatory policy, not optional.**
No password should ever be stored in plaintext under any circumstances. Bcrypt or an equivalent one-way hashing algorithm should be used at all times. Additionally, passwords and other sensitive credentials should never appear in UI elements, logs, or any file or document that doesn't strictly require them.

**4. Apply least privilege consistently.**
Users and systems should only have access to the data and functionality they absolutely need. If a piece of information doesn't need to be displayed, queried, or stored — it shouldn't be.

**5. Enforce authentication at the route level, not just the UI level.**
Hiding a link in the UI is not access control. Every protected route must independently verify that the requester has an active, valid session. A decorator or middleware applied at the route level ensures this check cannot be bypassed by navigating directly to a URL.

**6. Use signed, server-side sessions — never trust client-supplied identity.**
Session cookies must be cryptographically signed with a strong secret key stored in an environment variable. If a session cookie can be forged or tampered with, an attacker can impersonate any user in the system without knowing their password.
