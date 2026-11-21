# Railway secret rotation runbook (Boundry.AI)

Use this after Railway notifies you that customer environment variables may have been exposed. Rotate at **each provider first**, then update **every** Railway service (web + cron) and any local copy that reused the same value.

**Incident reference:** Railway platform notice (Oct 2026), status at [status.railway.com](https://status.railway.com).

---

## Quick commands (repo root)

```powershell
# 1) Inventory template + local .env key names (no secret values printed)
python tools/railway_breach_response.py inventory

# 2) Generate new app secrets → gitignored bundle (paste into Railway when deploys work)
python tools/railway_breach_response.py generate

# 3) After you paste new provider keys into the bundle, sync local .env (optional)
python tools/railway_breach_response.py apply-local

# 4) Scan tracked files for accidental key patterns
python tools/railway_breach_response.py scan-repo

# 5) Smoke-test production URL + cron header (set APP_URL and CRON_SECRET)
python tools/railway_breach_response.py smoke --url https://your-app.up.railway.app
```

Generated files (gitignored): `.railway_breach_inventory.md`, `.railway_rotation_bundle.env`, `.railway_breach_completion.md`.

---

## Phase 1 — Inventory

1. Subscribe to Railway incident / status updates.
2. For **each** Railway project, open **Variables** on **web** and **cron** services. Copy **names only** into `.railway_breach_inventory.md` (from `inventory` command).
3. Mark keys that appear in more than one project (rotate once at provider, update all services).

### Boundry MSSP variables (from code)

| Variable | Service | Rotate at |
|----------|---------|-----------|
| `DATABASE_URL` | Web (auto from Postgres plugin) | Railway Postgres → reset password |
| `SECRET_KEY` | Web | Generate (`generate` command) |
| `ANTHROPIC_API_KEY` | Web | console.anthropic.com |
| `RESEND_API_KEY` | Web | resend.com |
| `CRON_SECRET` | Web + all crons | `generate` command |
| `APP_URL` | Web + crons | No rotation |
| `PETA_EMAIL`, `FROM_EMAIL` | Web | No rotation |
| `ANALYST_USERNAME`, `ANALYST_PASSWORD` | Web | New password in `generate` / password manager |
| `DEMO_USERNAME`, `DEMO_PASSWORD` | Web | Same |
| `CRON_USER`, `CRON_PASS` | Cron (legacy pipeline) | Same |
| `ABUSEIPDB_API_KEY` | Web if set | abuseipdb.com |
| `TERMINAL_TOKEN`, `RESET_TOKEN` | If set | Regenerate |
| `FLASK_DEBUG` | Web | Must be `false` / unset in prod |

See also [RAILWAY_CRON.md](RAILWAY_CRON.md) and [RAILWAY_CRON_SETUP.md](RAILWAY_CRON_SETUP.md).

---

## Phase 2 — Rotate at providers (priority)

1. **Anthropic** — Revoke old keys; create new; check usage for anomalies.
2. **Resend** — Revoke old API key; create new; review send log.
3. **Postgres** — Railway Postgres service → rotate credentials; copy new `DATABASE_URL` to web service.
4. **Other** — AbuseIPDB, container registry, Stripe, etc. if present in inventory.
5. **App secrets** — Run `python tools/railway_breach_response.py generate` and keep `.railway_rotation_bundle.env` private.

Paste provider-issued values into the `PROVIDER_*` placeholder lines in the bundle before Railway deploy.

---

## Phase 3 — Railway dashboard

When variable updates / deploys are allowed:

1. Update **web** service from bundle + new `DATABASE_URL` + new API keys.
2. Update **every cron** with the same `CRON_SECRET` and `APP_URL`.
3. Redeploy web so analyst/demo env passwords sync into Postgres ([app.py](../app.py) startup).
4. Force password reset for any user created via `/register` (not env-seeded).

---

## Phase 4 — Local and copies

- Update `.env` via `apply-local` if keys were shared with Railway.
- Windows user env: `SECRET_KEY`, `GMAIL_APP_PASSWORD` if set.
- External schedulers (cron-job.org): new `X-Cron-Secret` header.
- GitHub Actions secrets: rotate if any matched Railway.

---

## Phase 5 — Log review

| Source | Look for |
|--------|----------|
| Railway HTTP logs | `/cron/*`, `/login`, `/run-agent`, unknown IPs |
| Anthropic | Token spikes, odd times |
| Resend | Unexpected sends |

Record findings in `.railway_breach_completion.md` (`python tools/railway_breach_response.py record`).

---

## Phase 6 — Verify

```powershell
python tools/railway_breach_response.py smoke --url $env:APP_URL
```

Manual: log in with new analyst password, confirm reports/cron email if Resend is configured.

---

*Boundry.AI · Jason Morgan*
