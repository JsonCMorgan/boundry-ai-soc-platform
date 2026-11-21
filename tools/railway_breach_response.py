#!/usr/bin/env python3
"""
Railway env-var breach response helpers for Boundry.AI.

Generates rotation material, inventories local .env keys, scans the repo,
and smoke-tests cron auth. Does not call Railway API (use dashboard).
"""

from __future__ import annotations

import argparse
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]

# Variables referenced for production / Railway (names only).
RAILWAY_CANDIDATE_VARS: tuple[str, ...] = (
    "DATABASE_URL",
    "SECRET_KEY",
    "ANTHROPIC_API_KEY",
    "RESEND_API_KEY",
    "CRON_SECRET",
    "APP_URL",
    "PETA_EMAIL",
    "FROM_EMAIL",
    "ANALYST_USERNAME",
    "ANALYST_PASSWORD",
    "DEMO_USERNAME",
    "DEMO_PASSWORD",
    "CRON_USER",
    "CRON_PASS",
    "ABUSEIPDB_API_KEY",
    "TERMINAL_TOKEN",
    "RESET_TOKEN",
    "SPLUNK_HEC_TOKEN",
    "GMAIL_APP_PASSWORD",
    "FLASK_DEBUG",
    "SEED_DB",
)

GENERATED_VARS: tuple[str, ...] = (
    "SECRET_KEY",
    "CRON_SECRET",
    "ANALYST_PASSWORD",
    "DEMO_PASSWORD",
    "CRON_PASS",
    "TERMINAL_TOKEN",
    "RESET_TOKEN",
)

PROVIDER_PLACEHOLDERS: tuple[str, ...] = (
    "DATABASE_URL",
    "ANTHROPIC_API_KEY",
    "RESEND_API_KEY",
    "ABUSEIPDB_API_KEY",
)

INVENTORY_PATH = ROOT / ".railway_breach_inventory.md"
BUNDLE_PATH = ROOT / ".railway_rotation_bundle.env"
COMPLETION_PATH = ROOT / ".railway_breach_completion.md"
ENV_PATH = ROOT / ".env"

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic", re.compile(r"sk-ant-api[a-zA-Z0-9\-_]{20,}")),
    ("resend", re.compile(r"re_[a-zA-Z0-9]{20,}")),
    ("generic_api", re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)['\"]?[a-zA-Z0-9_\-]{24,}")),
    ("postgres_url", re.compile(r"postgres(?:ql)?://[^\s'\"]+")),
)

SKIP_SCAN_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "backups",
    "instance",
    "content/private",
}


def _read_env_keys(path: Path) -> list[str]:
    """Return variable names from a dotenv file."""
    if not path.is_file():
        return []
    keys: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        keys.append(stripped.split("=", 1)[0].strip())
    return keys


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=value lines into a dict (no export support)."""
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, val = stripped.partition("=")
        out[key.strip()] = val.strip().strip('"').strip("'")
    return out


def _write_env_merge(path: Path, updates: dict[str, str]) -> None:
    """Merge updates into .env, preserving comments and unrelated keys."""
    lines: list[str] = []
    seen: set[str] = set()
    if path.is_file():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        new_lines.append(line)
    for key, val in updates.items():
        if key not in seen:
            new_lines.append(f"{key}={val}")
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def cmd_inventory() -> int:
    """Write inventory template and list local .env keys."""
    local_keys = _read_env_keys(ENV_PATH)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    body = f"""# Railway breach inventory (private — gitignored)

Generated: {now}

## Local `.env` keys present

{chr(10).join(f"- `{k}`" for k in local_keys) if local_keys else "- _(none — secrets may be Railway-only)_"}

## Expected Boundry variables (check each Railway project)

{chr(10).join(f"- [ ] `{v}`" for v in RAILWAY_CANDIDATE_VARS)}

## Project A — name: ____________________

### Web service variables (names only)

-

### Cron service variables (names only)

-

## Project B — name: ____________________

### Web service variables

-

### Cron service variables

-

## Reuse map (same key in multiple projects)

| Key | Projects |
|-----|----------|
| | |

## Provider rotation checklist

- [ ] Anthropic (`ANTHROPIC_API_KEY`)
- [ ] Resend (`RESEND_API_KEY`)
- [ ] Railway Postgres (`DATABASE_URL`)
- [ ] AbuseIPDB (if used)
- [ ] Container registry (if used)
- [ ] App secrets (`generate` command → bundle file)
"""
    INVENTORY_PATH.write_text(body, encoding="utf-8")
    print(f"Wrote {INVENTORY_PATH.relative_to(ROOT)}")
    print(f"Local .env keys: {', '.join(local_keys) if local_keys else '(none)'}")
    return 0


def _generate_secret(key: str) -> str:
    if key == "SECRET_KEY":
        return secrets.token_urlsafe(64)
    if key in ("CRON_SECRET", "TERMINAL_TOKEN", "RESET_TOKEN"):
        return secrets.token_urlsafe(32)
    return secrets.token_urlsafe(24)


def cmd_generate() -> int:
    """Generate new app secrets and a Railway paste bundle."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"# Boundry rotation bundle — generated {now}",
        "# DO NOT COMMIT. Paste into Railway when deploys are allowed.",
        "# Fill PROVIDER placeholders after revoking old keys at each vendor.",
        "",
    ]
    generated: dict[str, str] = {}
    for key in GENERATED_VARS:
        val = _generate_secret(key)
        generated[key] = val
        lines.append(f"{key}={val}")
    lines.append("")
    lines.append("# --- Paste after provider rotation ---")
    for key in PROVIDER_PLACEHOLDERS:
        lines.append(f"# {key}=PASTE_NEW_VALUE_HERE")
    lines.append("")
    lines.append("# Non-secret (verify, do not rotate)")
    lines.append("# APP_URL=https://web-production-31963.up.railway.app")
    lines.append("# PETA_EMAIL=simplypeta@gmail.com")
    lines.append("# FLASK_DEBUG=false")
    BUNDLE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        shown = BUNDLE_PATH.relative_to(ROOT)
    except ValueError:
        shown = BUNDLE_PATH.name
    print(f"Wrote {shown}")
    print("Next: revoke keys at Anthropic/Resend/Postgres, edit bundle placeholders, paste into Railway.")
    return 0


def cmd_apply_local() -> int:
    """Apply generated app secrets from bundle to local .env."""
    if not BUNDLE_PATH.is_file():
        print("Run `generate` first.", file=sys.stderr)
        return 1
    bundle = _parse_env_file(BUNDLE_PATH)
    updates = {k: bundle[k] for k in GENERATED_VARS if k in bundle and bundle[k]}
    if not updates:
        print("No generated secrets found in bundle.", file=sys.stderr)
        return 1
    _write_env_merge(ENV_PATH, updates)
    print(f"Updated {len(updates)} keys in {ENV_PATH.relative_to(ROOT)}")
    return 0


def cmd_scan_repo() -> int:
    """Scan git-tracked text files for accidental secret patterns."""
    import subprocess

    try:
        tracked = subprocess.check_output(
            ["git", "ls-files"],
            cwd=ROOT,
            text=True,
            errors="replace",
        ).splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("git ls-files failed", file=sys.stderr)
        return 1

    hits: list[str] = []
    for rel in tracked:
        path = ROOT / rel
        if not path.is_file():
            continue
        parts = set(path.parts)
        if parts & SKIP_SCAN_DIRS:
            continue
        if path.suffix.lower() in {".db", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if len(text) > 500_000:
            continue
        for label, pat in SECRET_PATTERNS:
            if pat.search(text):
                hits.append(f"{rel} ({label})")
                break

    if hits:
        print("POSSIBLE SECRETS IN TRACKED FILES (review manually):")
        for h in hits:
            print(f"  - {h}")
        return 2
    print("No secret patterns in git-tracked files (heuristic scan).")
    return 0


def cmd_smoke(url: str, cron_secret: str | None) -> int:
    """GET health-ish route and POST cron with secret (expect 404 if wrong/missing)."""
    base = url.rstrip("/")
    ok = True

    try:
        with urlopen(f"{base}/login", timeout=25) as resp:
            print(f"GET /login -> {resp.status}")
    except TimeoutError:
        print("GET /login timed out (Railway may be degraded or deploys blocked)")
        ok = False
    except (HTTPError, URLError) as exc:
        print(f"GET /login failed: {exc}")
        ok = False

    secret = cron_secret or _parse_env_file(BUNDLE_PATH).get("CRON_SECRET") or _parse_env_file(ENV_PATH).get(
        "CRON_SECRET", ""
    )
    if not secret:
        print("No CRON_SECRET (pass --cron-secret or run generate / set .env)")
        return 1 if not ok else 0

    req = Request(
        f"{base}/cron/breach-intel",
        method="POST",
        headers={"X-Cron-Secret": secret},
    )
    try:
        with urlopen(req, timeout=30) as resp:
            body = resp.read(500).decode("utf-8", errors="replace")
            print(f"POST /cron/breach-intel -> {resp.status} {body[:120]}")
    except HTTPError as exc:
        if exc.code == 404:
            print("POST /cron/breach-intel -> 404 (secret mismatch or CRON_SECRET unset on server)")
            ok = False
        else:
            print(f"POST /cron/breach-intel -> HTTP {exc.code}")
            ok = False
    except URLError as exc:
        print(f"POST /cron/breach-intel failed: {exc}")
        ok = False

    return 0 if ok else 1


def cmd_provider_checklist() -> int:
    """Print provider rotation URLs and append checklist to completion log."""
    steps = """
## Provider rotation (manual - do in browser before Railway paste)

1. **Anthropic** - https://console.anthropic.com/settings/keys  
   Revoke every key that was ever in Railway. Create a new key. Paste into bundle as `ANTHROPIC_API_KEY`.

2. **Resend** - https://resend.com/api-keys  
   Revoke old key. Create new. Paste as `RESEND_API_KEY`. Review recent sends.

3. **Railway Postgres** - Dashboard > Postgres service > Credentials / Connect  
   Reset password or rotate credentials. Copy new `DATABASE_URL` to web service (and any DB consumer).

4. **AbuseIPDB** (if in inventory) - https://www.abuseipdb.com/account/api  
   Rotate `ABUSEIPDB_API_KEY`.

5. **Container registry** (if Railway mentioned registry creds in your project)  
   Revoke token at GitHub/GitLab/Docker Hub and reissue.

6. **Reuse rule** - Same key in multiple Railway projects: rotate once, update all services.
"""
    print(steps.strip())
    if COMPLETION_PATH.is_file():
        COMPLETION_PATH.write_text(
            COMPLETION_PATH.read_text(encoding="utf-8") + steps,
            encoding="utf-8",
        )
    return 0


def cmd_env_audit() -> int:
    """Print which candidate vars are set in process env (names only)."""
    import os

    print("Process environment (names only, values not shown):")
    for key in RAILWAY_CANDIDATE_VARS:
        if os.environ.get(key, "").strip():
            print(f"  set: {key}")
    local = _read_env_keys(ENV_PATH)
    if local:
        print(f"Local .env keys: {', '.join(local)}")
    return 0


def cmd_railway_paste_guide() -> int:
    """Write gitignored paste order for Railway dashboard."""
    path = ROOT / ".railway_paste_order.md"
    text = """# Railway paste order (private)

Use after provider rotation and when Railway allows variable updates.

1. Postgres: set `DATABASE_URL` on **web** service.
2. Paste from `.railway_rotation_bundle.env`: `SECRET_KEY`, `CRON_SECRET`, passwords.
3. Paste provider keys: `ANTHROPIC_API_KEY`, `RESEND_API_KEY`, optional `ABUSEIPDB_API_KEY`.
4. **Same** `CRON_SECRET` + `APP_URL` on every **cron** service.
5. Redeploy web (syncs `ANALYST_PASSWORD` / `DEMO_PASSWORD` into Postgres).
6. Re-run: `python tools/railway_breach_response.py smoke --url <APP_URL>`
"""
    path.write_text(text, encoding="utf-8")
    print(f"Wrote {path.relative_to(ROOT)}")
    return 0


def cmd_record() -> int:
    """Append completion template for private recordkeeping."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    block = f"""
## Rotation log entry — {now}

- Railway notice date: 2026-10-22
- Rotation completed date: __________
- Projects updated (all services): __________
- Providers rotated: Anthropic / Resend / Postgres / other: __________
- Log review done: yes / no
- Suspicious activity: none / describe: __________
"""
    if COMPLETION_PATH.is_file():
        COMPLETION_PATH.write_text(COMPLETION_PATH.read_text(encoding="utf-8") + block, encoding="utf-8")
    else:
        COMPLETION_PATH.write_text(
            "# Railway breach response — private completion log (gitignored)\n" + block,
            encoding="utf-8",
        )
    print(f"Updated {COMPLETION_PATH.relative_to(ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Railway breach response helpers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("inventory", help="Write .railway_breach_inventory.md")
    sub.add_parser("generate", help="Write .railway_rotation_bundle.env")
    sub.add_parser("apply-local", help="Merge generated secrets into .env")
    sub.add_parser("scan-repo", help="Heuristic scan of git-tracked files")
    sub.add_parser("record", help="Append completion log template")
    sub.add_parser("provider-checklist", help="Provider rotation URLs + completion log")
    sub.add_parser("railway-paste-guide", help="Write .railway_paste_order.md")
    sub.add_parser("env-audit", help="List set candidate env var names (no values)")

    smoke_p = sub.add_parser("smoke", help="Smoke-test APP_URL and cron auth")
    smoke_p.add_argument("--url", required=True, help="Production base URL")
    smoke_p.add_argument("--cron-secret", default="", help="Override CRON_SECRET")

    args = parser.parse_args()
    handlers = {
        "inventory": cmd_inventory,
        "generate": cmd_generate,
        "apply-local": cmd_apply_local,
        "scan-repo": cmd_scan_repo,
        "record": cmd_record,
        "provider-checklist": cmd_provider_checklist,
        "railway-paste-guide": cmd_railway_paste_guide,
        "env-audit": cmd_env_audit,
    }
    if args.cmd == "smoke":
        return cmd_smoke(args.url, args.cron_secret or None)
    return handlers[args.cmd]()


if __name__ == "__main__":
    raise SystemExit(main())
