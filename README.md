# Boundry.AI — SOC Operations Platform

I'm building Boundry.AI as a cybersecurity services company targeting small-to-medium businesses in regulated industries — the dispensaries, medical practices, and law firms that need real security monitoring but can't get near an enterprise contract. This platform is the operational tool I'm building to run it.

My background is in physical security — almost a decade working the door at bars and venues. A bouncer's job and a SOC analyst's job are more alike than people think: you read the room, spot the threat before it becomes an incident, and act fast when it does. Boundry.AI is that same instinct, now with real tools behind it instead of just my hands and wits.

---

## Platform Overview

| Module | Description |
|--------|-------------|
| 🖥 **Control Room** | Analyst HQ — live threat posture, VPN status, client list, one-click client onboarding |
| 📡 **SIEM** | Real-time event feed from Windows Event Log, firewall, syslog, and client app sources |
| 🔎 **SPL Query Engine** | Splunk-style query language over the event store — filter, aggregate, export |
| 📋 **Compliance Dashboard** | PCI DSS 4.0 auto-assessment + 10 industry frameworks (HIPAA, GLBA, METRC, etc.) |
| 🛡 **Reports** | Client-facing findings portal with triage workflow, notes, and escalation tracking |
| 🎓 **SOC Training** | MITRE ATT&CK scenario lab with XP rewards and performance scorecard |
| 📘 **CISSP Study Hub** | 8-domain exam prep woven throughout the analyst workflow |

> **🧭 In plain English —** This is the dashboard I sit behind to watch over a client's security. One screen shows me what's happening right now (the Control Room), another is the raw feed of everything going on (the SIEM), and another turns those events into a clean report a client can actually read. The training and CISSP pieces keep my own skills sharp while I run it.

---

## How Client Onboarding Works

The whole point of the platform is turning "I signed a client" into "I'm monitoring them" with as little friction as possible.

1. **Add the client** — From the Control Room I hit **+ Add Client** and enter their name, email, business, and industry.
2. **They get set up automatically** — The system creates their account, generates a unique **API key**, and emails them a one-time link to set their own password.
3. **Install monitoring** — I copy a small code snippet (pre-filled with their API key) into their web app. It quietly forwards security events to Boundry.AI.
4. **Events flow in, tagged to them** — Every event a client's app sends hits the `/api/ingest` endpoint, authenticated by their key, and is stored against *their* account only.
5. **Reports generate; the client sees them** — Boundry.AI's analyst engine turns those events into incident reports. The client logs into their portal and sees only their own reports, health score, and findings.

> **🧭 In plain English —** Think of the API key as a client's own private mailbox key. Their website drops security events into their mailbox, and only I — as their analyst — and they can see what's inside. No client can ever see another client's mail. Signing a client to actively monitoring them is about a five-minute job, not a week of setup.

---

## What's Live Today vs. Roadmap

I keep an honest line between what works right now and what's still ahead — it's how I stay "beyond reproach" with clients.

### ✅ Model A — App Security Monitoring (LIVE)
A client installs a snippet in their website or app that forwards security events (failed logins, injection attempts, account enumeration, etc.) to Boundry.AI. Those events are analysed, turned into professional incident reports, and shown to the client. **This works today and is ready to sell** to any business with a web presence — e-commerce, SaaS, a booking system, a POS with a login.

### 🚧 Model B — Full Infrastructure Monitoring (ROADMAP)
Monitoring a client's actual servers and network — not just their web app — by installing a lightweight collector agent that ships their system logs, Windows events, and firewall logs into a per-client SIEM. **Deliberately deferred** until 2–3 paying Model A clients prove the model. The big lift is the collector agent; the rest is database work I already have patterns for.

> **🧭 In plain English —** Right now I can protect the part of a client's business that lives on the internet — their website and apps — and that alone is a real, sellable service. The bigger version, where I'm watching their whole office network and every server, is the next chapter. I'm not building it on spec; I'll build it when a paying client asks for it. That keeps me lean and keeps my promises real.

---

## Key Features

### Security Operations
- **Live SIEM feed** with severity bucketing (Critical / High / Medium / Low), multi-source filtering, multi-column sort, and 15-second auto-refresh
- **SPL-lite query engine** — write Splunk-style queries (`severity=HIGH | stats count by src_ip | sort -count`) against the live event store
- **MITRE ATT&CK integration** — findings mapped to attacker techniques; each links to tactics, detection guidance, and remediation steps
- **Incident response playbooks** — five-phase response guides (ransomware, phishing/BEC, data breach, account compromise, insider threat) in both technical (YAML) and plain-language versions
- **Automated threat simulation** — generates realistic Windows Event, firewall, and syslog events for training and demos

> **🧭 In plain English —** The SIEM is the security camera feed for a client's digital front door. The query engine lets me rewind and ask specific questions ("show me every failed login from this address"). MITRE ATT&CK is the industry's playbook of how attackers operate — I map what I see to it so I know what a threat is *trying* to do. And the response playbooks are the step-by-step "if this happens, do this" guides, written once for me and once in language a business owner can follow.

### Compliance
- **PCI DSS 4.0** auto-assessment against live scan findings — 12 requirements scored automatically
- **10 industry frameworks** — Cannabis (METRC), Healthcare (HIPAA), Financial (GLBA/SOX), Legal, Retail, Hospitality, Real Estate, Construction, Non-profit, General
- Per-client industry assignment; analysts can preview any framework

> **🧭 In plain English —** Regulated businesses (dispensaries, clinics, law firms) have rules they *must* follow or face fines. The compliance dashboard checks a client against the exact rulebook for their industry and shows where they stand — turning a scary audit word like "PCI DSS" into a simple checklist.

### Client Management
- **One-click onboarding** — create a client, auto-issue their API key, and send a password-setup link in a single step
- **Three-role system** — Analyst (full ops), Client (their reports only), Demo (isolated sandbox showcase)
- **Client reports portal** with status workflow (New → Reviewing → Escalated → Closed)
- **Analyst notes** with discipline tracking (a "notes-before-triage" metric that keeps my investigation honest)
- **Weekly digest emails** via Resend

> **🧭 In plain English —** Everything I need to run clients as a business, not just a tech demo. I can onboard someone in minutes, keep each client's data walled off from every other client, and even hand a prospect a "demo" login that lets them click around a realistic dashboard without ever touching a real client's data.

### Analyst Experience
- **Live Ops / Study Mode toggle** — one click strips all educational scaffolding for a clean professional view, or surfaces full CISSP exam context throughout the UI
- **XP + level system** — resolving findings, completing training, and reading MITRE detail pages all earn XP
- **Scorecard** — tracks triage speed, escalation rate, and investigation discipline

> **🧭 In plain English —** I built the platform to make me a better analyst while I use it. It quietly scores how fast and disciplined I am, and doubles as my CISSP exam prep — so running the business and levelling up my own credentials happen at the same time.

---

## Security & Data Isolation

- **Session-based authentication** with bcrypt password hashing
- **TOTP two-factor authentication (2FA)** with QR-code setup (Google Authenticator compatible)
- **CSRF protection** on every state-changing form (Flask-WTF)
- **Adjustable login throttle** — analyst-tunable rate limit (Normal / Elevated / Lockdown) that can be tightened live during a brute-force attempt, with every throttled attempt logged to the SIEM
- **Per-client data isolation** — every client-facing query is scoped by `owner_id`; a client can only ever see their own reports, events, and findings (audited, no cross-client leakage)
- **Demo sandbox** — the demo account sees only its own seeded data and is blocked from modifying any real client's records
- **One-time, time-limited setup and reset tokens** for password flows

> **🧭 In plain English —** This is a security company, so the platform itself has to be locked down harder than what it protects. Each client's data lives behind its own locked door — I've checked every door, and none of them open into someone else's room. If someone tries to brute-force their way into a login, I can crank the lock tighter with one click and watch every attempt show up on my feed. And the demo I show prospects is a sealed playground — they can push every button without ever touching a real client.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 · Flask |
| Database | PostgreSQL (production, Railway) · SQLite (local dev) — accessed via raw parameterised SQL, no ORM |
| Auth | Session-based · bcrypt · PyOTP (TOTP 2FA) |
| Security | Flask-WTF (CSRF) · Flask-Limiter (rate limiting) |
| Email | Resend API |
| AI | Local Ollama (dev) with Anthropic Claude fallback (production) |
| Frontend | Jinja2 · Vanilla JS · CSS custom properties |
| Deployment | Railway · Gunicorn |
| Log ingestion | `/api/ingest` API · Windows Event / firewall / syslog collectors |

> **🧭 In plain English —** It's built on boring, reliable, well-understood tools on purpose — Python and Flask are the workhorses of the web, and I talk to the database directly with hand-written queries so there's no magic hiding bugs. In production it runs on Railway with a proper PostgreSQL database. The AI that writes reports runs locally and for free on my own machine while I build, and switches to Claude in the cloud when it's live.

---

## Architecture

```
        A client's website / app
                  │
                  │  security events (X-API-Key)
                  ▼
        ┌───────────────────┐
        │   /api/ingest     │  ← authenticated, tagged to owner_id
        └───────────────────┘
                  │
┌─────────────────┼───────────────────────────────┐
│                 ▼         Boundry.AI              │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ Control  │  │   SIEM   │  │  Compliance   │   │
│  │  Room    │  │  + SPL   │  │  Dashboard    │   │
│  └──────────┘  └──────────┘  └───────────────┘   │
│                                                   │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐   │
│  │ Reports  │  │ Training │  │ CISSP Study   │   │
│  │  Portal  │  │   Lab    │  │     Hub       │   │
│  └──────────┘  └──────────┘  └───────────────┘   │
│                                                   │
│         Flask · PostgreSQL / SQLite               │
└───────────────────────────────────────────────────┘
        ▲                        ▲
  Windows Event            Firewall / Syslog
  Log Collector            Collectors (host)
```

> **🧭 In plain English —** Follow the arrows: a client's website sends its security events up top, they land in a locked, labelled inbox (`/api/ingest`), and from there everything fans out into the tools I use to make sense of it. The collectors at the bottom are how I watch my own infrastructure today — and they're the foundation for watching a client's whole network tomorrow (Model B).

---

## Roles

| Role | Access |
|------|--------|
| `analyst` | Full platform — SIEM, SPL, compliance, training, CISSP, all client reports |
| `client` | Their own reports portal + compliance dashboard, nothing else |
| `demo` | Isolated sandbox — a realistic showcase populated with fake data only |

> **🧭 In plain English —** Three kinds of logins: me (I see everything), a client (they see only their own stuff), and a demo login I can safely hand a prospect (it looks fully live but is a sealed sandbox with no real data in it).

---

## Local Setup

```bash
git clone https://github.com/JsonCMorgan/boundry-ai-soc-platform.git
cd boundry-ai-soc-platform
pip install -r requirements.txt

# Environment variables (local dev)
export SECRET_KEY=your-secret-key           # auto-generated locally if unset
export APP_URL=http://localhost:5000
export RESEND_API_KEY=your-resend-key        # optional — enables onboarding/alert emails

python app.py
```

The app auto-creates the SQLite database on first run. In production on Railway, add a PostgreSQL plugin (auto-sets `DATABASE_URL`) and set `SECRET_KEY`, `ANTHROPIC_API_KEY`, `RESEND_API_KEY`, `APP_URL`, and `CRON_SECRET` as service variables.

> **🧭 In plain English —** To run it on your own machine: grab the code, install the dependencies, and start it — the database builds itself. Secrets like API keys are never stored in the code; they're supplied separately at runtime, so nothing sensitive ever ends up on GitHub.
