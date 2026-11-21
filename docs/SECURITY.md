# Security posture (`main` branch)

Boundry.AI started life as a **deliberately vulnerable Flask app** for AppSec practice. It has since been hardened step by step, which is the Secure Development Lifecycle in miniature. This page tells a reviewer which "weird looking" things are intentional so nobody mistakes a lab exhibit for a real bug.

## Two branches, two purposes

| Branch | Purpose | Run where |
|--------|---------|-----------|
| `main` | Hardened platform. All lab vulnerabilities below are fixed. | Local dev, Railway |
| `vulnerable` | Keeps the exploitable versions for hands-on practice. | **localhost only** |

Compare them with `git diff main..vulnerable -- app.py`.

## Lab findings and their status on `main`

| OWASP 2021 | Route | Lab issue | Status on `main` | Test proving it |
|------------|-------|-----------|------------------|-----------------|
| A03 Injection | `/search` | SQL injection via string-built query | **Fixed.** Parameterized query through `db_fetchall` + `PH` placeholder | `test_search_sql_injection_payload_is_data` |
| A03 Injection | `/greeting` | Reflected XSS if the template used `\|safe` | **Fixed.** Default Jinja2 auto-escaping | `test_greeting_escapes_script_tag` |
| A05 Misconfiguration | `app.py` | Debug mode exposes stack traces | **Mitigated.** Debug only when `FLASK_DEBUG` is truthy | n/a |
| A01 Broken Access Control | ops routes | Client accounts reaching analyst pages | **Fixed.** Client/demo route guard returns 404 | `test_client_role_cannot_reach_ops_routes` |
| A07 Auth Failures | `/login`, `/register` | Brute force, weak passwords | **Fixed.** Rate limits, 12+ char policy, bcrypt, optional TOTP 2FA | `test_register_*`, `test_login_throttle_is_logged_to_siem` |

## Intentional lab design (not bugs)

- **`/search` shows a password column.** On `main` that column holds **bcrypt hashes**, not plaintext, and the route is analyst-only. It stays visible on purpose as a "sensitive data exposure" teaching exhibit.
- **Seeded lab accounts** (`admin`, `alice`, `bob`) are only created when `SEED_DB=true`. Never set that in production.
- **Training content mentions attacks** (ransomware, SQLi payloads, phishing). That text is lesson material, not executable attack tooling.

## Guardrails in CI

Every push runs:

1. **gitleaks** secrets scan over the full git history (`.gitleaksignore` lists reviewed false positives)
2. **ruff** lint gate for real bugs (syntax errors, undefined names)
3. **pytest** suite, including the security regression tests above

## Reporting a problem

Found something that is not on this list? Email json.c.morgan@gmail.com. Please do not open a public issue for anything exploitable.
