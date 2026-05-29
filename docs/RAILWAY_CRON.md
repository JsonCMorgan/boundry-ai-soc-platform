# Railway Cron Configuration — Boundry.AI

How to configure the two automated cron jobs on Railway.

---

## Prerequisites

Both cron jobs require a `CRON_SECRET` environment variable set on Railway.
This is a long random string used to authenticate the cron request.

Generate one:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set it in Railway:
→ Your Service → Variables → Add `CRON_SECRET` = (your generated value)

Also set:
- `PETA_EMAIL` = `simplypeta@gmail.com` (recipient for daily report)
- `APP_URL` = your Railway app URL (e.g. `https://web-production-31963.up.railway.app`)
- `RESEND_API_KEY` = your Resend API key (required for email sending)

---

## Cron Job 1 — Weekly Client Digest (Monday 9 AM)

**What it does:** Sends each client a plain-English weekly security summary — their health score, report count, and threat count for the past 7 days.

**Railway cron setup:**
1. Railway Dashboard → Your Project → Add Service → Cron
2. Schedule: `0 9 * * 1` (every Monday at 09:00 UTC)
3. Command:
```bash
curl -s -X POST $APP_URL/cron/weekly-digest \
     -H "X-Cron-Secret: $CRON_SECRET"
```

---

## Cron Job 2 — Daily EOD Report (Every day 8 PM)

**What it does:** Sends Peta a daily end-of-day summary covering everything that happened on the platform that day — SIEM events, new findings, ransomware indicators, training activity, breach intel, and platform stats.

**Railway cron setup:**
1. Railway Dashboard → Your Project → Add Service → Cron
2. Schedule: `0 20 * * *` (every day at 20:00 UTC)
3. Command:
```bash
curl -s -X POST $APP_URL/cron/daily-report \
     -H "X-Cron-Secret: $CRON_SECRET"
```

---

## Testing Locally

You can trigger either cron manually from your terminal to test:

```bash
# Test daily report (replace with your local URL and CRON_SECRET)
curl -s -X POST http://localhost:5000/cron/daily-report \
     -H "X-Cron-Secret: your-secret-here"

# Test weekly digest
curl -s -X POST http://localhost:5000/cron/weekly-digest \
     -H "X-Cron-Secret: your-secret-here"
```

Both return JSON on success:
```json
{ "status": "ok", "sent": true, "recipient": "simplypeta@gmail.com", ... }
```

---

## Cron Schedule Reference

| Schedule | Expression |
|---|---|
| Every day at 8 PM UTC | `0 20 * * *` |
| Every Monday at 9 AM UTC | `0 9 * * 1` |
| Every hour | `0 * * * *` |
| Every 15 minutes | `*/15 * * * *` |

---

## Environment Variables Checklist

| Variable | Required For | Where to Get |
|---|---|---|
| `CRON_SECRET` | Both crons | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `RESEND_API_KEY` | Email sending | resend.com → API Keys |
| `APP_URL` | Email links | Your Railway app URL |
| `PETA_EMAIL` | Daily report | `simplypeta@gmail.com` |
| `SECRET_KEY` | Flask sessions | `python -c "import secrets; print(secrets.token_hex(32))"` |

---

*Boundry.AI SOC Platform · Jason Morgan*
