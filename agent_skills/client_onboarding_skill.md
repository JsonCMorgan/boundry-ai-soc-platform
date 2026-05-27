# Client Onboarding Skill — Boundry.AI

Onboard a new paying client onto the Boundry.AI command center: account, deployment checklist, welcome comms, first-week timeline.

---

## Purpose

Take a signed (or verbal) client from intake through first monitoring deliverable without missing security or revenue steps.

## Prerequisites

- Jason has analyst login to Boundry.AI Flask app
- Client contact name, email, and scope agreed
- Pre-client checklist reviewed (`.cursorrules` → PRE-CLIENT CHECKLIST)
- `C:\Dev\launch-boundry-ai.bat` or equivalent launcher available

---

## Inputs

| Input | Required | Example |
|-------|----------|---------|
| `client_name` | Yes | `GreenLeaf Dispensary` |
| `client_username` | Yes | `greenleaf` (3–50 chars) |
| `contact_email` | Yes | `owner@greenleaf.example` |
| `scope` | Yes | `audit_only` \| `siem` \| `both` |
| `vpn_required` | Yes | `true` / `false` |
| `splunk_hec` | Optional | `true` / `false` |

---

## Steps

### 0. CONCEPT — Progress file

Create `agent_tasks/client_onboarding_<client_username>_progress.md`.

---

### 1. Intake checklist

Record in progress file:

- [ ] Client legal/business name
- [ ] Primary contact + email
- [ ] Scope: audit only / SIEM monitoring / both
- [ ] VPN requirement (NordVPN kill switch mandatory if yes)
- [ ] Splunk HEC optional (client has Splunk? token ready?)
- [ ] Pricing tier agreed (audit one-time vs monthly retainer)
- [ ] Data handling acknowledged (local-first, Ollama on Jason's machine)

---

### 2. Create client user / tenant in Boundry.AI

**Current production path** (no admin UI yet):

#### Option A — Register route (creates `client` role by default)

```
GET  /register          — registration form
POST /register          — username, password, confirm
```

- Default DB role: `client` (`users.role` default)
- Auto-generates `api_key` on insert (~line 1129 `app.py`)
- Password policy: 12+ chars, upper, number, special char

Jason creates account manually in browser, or guides client through register.

#### Option B — Verify in Control Room

```
GET /control-room
```

Confirm new user appears in client list (`role = 'client'`).

#### Option C — Integration page (analyst only)

After user exists, note client `id` from control room:

```
GET /analyst/client/<client_id>/integration
```

Shows:
- Client `api_key` for `/api/ingest`
- Ingest URL: `{APP_ROOT}/api/ingest`
- Pre-filled integration code for client's app

**Ingest API** (for client app monitoring):
```
POST /api/ingest
X-API-Key: <client_api_key>
Content-Type: application/json
{"event_type": "LOGIN_FAILED", "username": "...", "ip": "...", "extra": ""}
```

Valid event types: `LOGIN_FAILED`, `LOGIN_SUCCESS`, `SEARCH`, `REGISTER_SUCCESS`, `XSS_ATTEMPT`, `DIRECTORY_TRAVERSAL`, `PRIV_ESC_ATTEMPT`, `ACCOUNT_ENUM`.

Record `client_id`, `username`, and `api_key` (last 4 chars only) in progress file.

---

### 3. Deployment checklist (Jason's machine / client site)

Mark each item in progress file:

**Security (do first):**
- [ ] `SECRET_KEY` env var set (not `dev-only-secret`)
- [ ] `FLASK_DEBUG=false` in production
- [ ] NordVPN kill switch ON if `vpn_required`
- [ ] Review open ports on monitoring host (`POST /scan/network` or `bai scan -n`)

**Environment variables:**
- [ ] `SECRET_KEY` — session signing
- [ ] `DATABASE_URL` — PostgreSQL for production (unset = SQLite local)
- [ ] `GMAIL_APP_PASSWORD` — email alerts (`alert_monitor.py`)
- [ ] `SPLUNK_HEC_TOKEN` + `SPLUNK_HEC_URL` — if Splunk enabled
- [ ] `SPLUNK_INDEX` — default `main`

**Operational:**
- [ ] `.terminal_token` present (auto-written on Flask startup — for `bai` module)
- [ ] `vpn_monitor.py` thread running (check `GET /api/vpn/status`)
- [ ] `siem_collector.py` threads active (events appearing on `GET /siem`)
- [ ] Task Scheduler: `BoundryAI-AutoReport` (8AM), `BoundryAI-AlertMonitor` (15min)
- [ ] Ollama running: `http://localhost:11434`
- [ ] Launch script: `C:\Dev\launch-boundry-ai.bat`

**Initial scans (if scope includes audit):**
```
POST /scan/machine     — Windows security audit
POST /scan/network     — Network exposure scan
GET  /scan/findings    — Review open findings
```

Terminal equivalents: `bai scan`, `bai scan -n`, `bai findings`

---

### 4. Welcome email draft

Produce plain-text email in progress file (Boundry.AI tone — direct, no jargon overload):

```
Subject: Welcome to Boundry.AI — Your Security Monitoring Is Active

Hi {contact_first_name},

Welcome to Boundry.AI. Your account is set up and we're now monitoring {scope_summary}.

What we set up for you:
- Boundry.AI command center access: {app_url}
- Username: {client_username}
- {siem_line_if_applicable}
- {audit_line_if_applicable}

What happens next:
- Week 1: Baseline monitoring and initial findings review
- Week 2: First weekly SIEM report (if on monitoring retainer)
- You can reach us anytime at jason.morgan@boundry.ai

Your data stays on our secure local infrastructure — nothing is sent to third-party AI clouds unless you've approved fallback mode.

— Jason Morgan
Boundry.AI | Local-first cybersecurity for SMBs
```

Jason sends manually until transactional email is automated.

---

### 5. First-week deliverables timeline

| Day | Deliverable |
|-----|-------------|
| Day 0 | Account live, VPN verified, SIEM events flowing |
| Day 1 | Baseline scan (`/scan/machine`) if audit scope |
| Day 2–3 | Review CRITICAL/HIGH findings — run `new_finding_triage_skill` if needed |
| Day 5 | Internal checkpoint — enough events for meaningful weekly report? |
| Day 7 | First `@weekly_siem_report_skill` run (if SIEM scope) |

---

### 6. Stripe — new customer setup

When Stripe MCP connected (see `docs/MCP_SETUP.md`):

1. `create_customer` — name, email, metadata `{boundry_client: "<client_username>"}`
2. `create_product` / `create_price` — if SKUs not yet created
3. `list_subscriptions` or create subscription for agreed tier
4. Record Stripe customer ID in progress file

**Without MCP:** Create customer in Stripe Dashboard manually.

---

### 7. REVISION_COMPLETE — Verification

- [ ] Client user exists (`/control-room`)
- [ ] Integration page accessible (`/analyst/client/<id>/integration`)
- [ ] SECRET_KEY and FLASK_DEBUG verified
- [ ] VPN status green if required (`/api/vpn/status`)
- [ ] SIEM events visible (`/siem` or `/api/siem/events`)
- [ ] Welcome email draft in progress file
- [ ] First-week timeline recorded
- [ ] Stripe customer ID recorded (or BLOCKED)

---

### 8. TASK_COMPLETE

Handoff to Jason:
- Send welcome email
- Schedule Day 7 weekly report
- Add client to Notion CRM (when Notion MCP configured)

---

## Artifacts

| Artifact | Path |
|----------|------|
| Progress file | `agent_tasks/client_onboarding_<client_username>_progress.md` |
| Welcome email | Inside progress file |
| Integration details | Progress file (client_id, ingest URL — not full api_key in git) |

---

## Boundry.AI routes referenced

| Route | Method | Use |
|-------|--------|-----|
| `/register` | GET/POST | Create client account |
| `/control-room` | GET | Verify client listed |
| `/analyst/client/<id>/integration` | GET | API key + ingest setup |
| `/api/ingest` | POST | Client event ingestion |
| `/scan/machine` | POST | Initial audit |
| `/scan/network` | POST | Network scan |
| `/scan/findings` | GET | Open findings |
| `/api/vpn/status` | GET | VPN check |
| `/siem` | GET | Confirm SIEM live |

---

## Revenue hook

Onboarding ends with Stripe customer + subscription for the agreed tier. First invoice may be audit (one-time) plus monitoring (recurring). Cross-reference `weekly_siem_report_skill.md` for ongoing billing rhythm.

---

## Verification

All items in step 7 checked. Status `TASK_COMPLETE` in progress file.
