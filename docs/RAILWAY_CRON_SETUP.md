# Railway Cron Job Setup — Boundry.AI Demo Pipeline

This document explains how to set up a Railway cron job that automatically
simulates attack events and runs the threat detection agent every hour. The
result is a continuously updating demo dashboard — useful for showing clients
what the monitoring product looks like in action.

---

## What the cron job does

1. **POST /simulate-attack** — writes 8 realistic fake attack events to the
   security log (5 failed logins, 1 success, 2 SQL injection attempts).
2. **POST /run-agent** — reads the log, detects threats, calls the Claude API,
   and saves a plain-English incident report to the PostgreSQL `reports` table.

Because the reports table is in PostgreSQL (not the filesystem), reports
survive Railway redeployments.

---

## Prerequisites

| Item | Where to set it |
|---|---|
| `SECRET_KEY` | Railway → your service → Variables |
| `ANTHROPIC_API_KEY` | Railway → your service → Variables |
| `DATABASE_URL` | Set automatically when you add a PostgreSQL plugin |
| An active Boundry.AI user account | Register at `/register` after first deploy |

> **Important:** Without `ANTHROPIC_API_KEY`, the agent still saves a
> placeholder report (so the dashboard populates), but the report content will
> note that AI generation is disabled.

---

## Step 1 — Get your dashboard credentials

After deploying, visit `https://<your-app>.up.railway.app/register` and create
a user account. You will need a valid session cookie to call the protected
endpoints. The cron job uses `curl` with Basic-Auth-style cookie handling.

Because Railway cron jobs cannot maintain a browser session, the recommended
approach is to use a **cron-specific API token** pattern. The simplest option
for this app is to call the endpoints via a small shell script that logs in
first and carries the session cookie.

---

## Step 2 — Create the cron script

Create a file `cron/run_demo_pipeline.sh` in your repo:

```bash
#!/bin/bash
# Boundry.AI hourly demo pipeline
# Logs in, simulates attacks, then triggers the agent.

set -e

BASE_URL="${APP_URL:-https://web-production-31963.up.railway.app}"
USERNAME="${CRON_USER:-admin}"
PASSWORD="${CRON_PASS}"   # Set as Railway env var — never hardcode

COOKIE_JAR=$(mktemp)

# 1. Log in and capture session cookie
curl -s -c "$COOKIE_JAR" -X POST "$BASE_URL/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  -L --max-redirs 5 > /dev/null

# 2. Simulate attack events
curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/simulate-attack" | jq .

# 3. Run the threat detection agent
curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/run-agent" | jq .

rm -f "$COOKIE_JAR"
echo "Pipeline complete."
```

Commit this file and set it executable (`chmod +x cron/run_demo_pipeline.sh`).

---

## Step 3 — Configure the Railway cron service

Railway cron jobs are a separate service that runs a command on a schedule.

1. In the Railway dashboard, click **New** → **Empty Service**.
2. Connect it to the same GitHub repo.
3. In the service settings, set the **Start Command** to:

   ```
   bash cron/run_demo_pipeline.sh
   ```

4. Under **Settings → Cron Schedule**, enter:

   ```
   0 * * * *
   ```

   This runs the script at minute 0 of every hour (e.g. 09:00, 10:00, 11:00).

5. Add these environment variables to the **cron service** (not the web service):

   | Variable | Value |
   |---|---|
   | `APP_URL` | `https://web-production-31963.up.railway.app` |
   | `CRON_USER` | `admin` (or whichever account you created) |
   | `CRON_PASS` | The account's password — set as a secret |

---

## Step 4 — Add ANTHROPIC_API_KEY to the web service

The `/run-agent` endpoint calls the Claude API to generate the plain-English
report. Without this key it saves a placeholder, so the dashboard still works
but reports say "AI generation disabled".

1. In the Railway dashboard, open your **web service** (not the cron service).
2. Go to **Variables**.
3. Add:
   ```
   ANTHROPIC_API_KEY = sk-ant-...
   ```
4. Railway will redeploy automatically.

---

## Cron schedule reference

| Schedule string | Meaning |
|---|---|
| `0 * * * *` | Every hour on the hour |
| `*/30 * * * *` | Every 30 minutes |
| `0 9 * * 1-5` | 9am Monday–Friday |
| `0 0 * * *` | Midnight every day |

---

## Verifying it works

After the first cron run, log in to the Boundry.AI dashboard at `/reports`.
You should see a new incident report with a brute force finding and two SQL
injection findings. If the report says "ANTHROPIC_API_KEY is not configured",
add the key to your web service variables and re-run.

---

*Boundry.AI — Security that speaks your language.*
