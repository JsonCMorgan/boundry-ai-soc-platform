# Boundry.AI — SOC Operations Platform

So here's what Boundry.AI actually is. I'm building a Security Company for the businesses everyone else writes off as too small to bother with — the dispensaries, the clinics, the law firms. They handle sensitive data every single day, they're legally on the hook for it, and yet the enterprise security shops won't give them the time of day. I've always wanted to fight for the little guy, and now I've got my arsenal ready.

Now, my roots are in physical security — almost ten years working the door at bars and venues. But I didn't stop at the door. I earned my Cybersecurity degree from York University in Ontario in 2024, and I'm ISC(2) certified. So I'm not just some bouncer who bought a computer — I'm a full-fledged Security Professional who can handle a threat whether it walks through the front door or comes through the firewall. A Bouncer and a SOC Analyst really do the same job. You read the room, you spot the problem before it becomes an incident, and you stay calm and move fast when it does. The difference now is I've got the education, the certification, and a real arsenal behind me — not just my hands and my read on people.

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

> **🗣️ Real Talk —** Think of this as my command center. One screen shows me what's happening with a Client right now. The next is a metal detector that every bit of activity on their system walks through — it runs around the clock and goes off the second something dangerous tries to slip past. And the last one is my Clipboard — every respectable Door Man's got one — it takes all that chaos and writes it up clean, so the Client can actually read it without a security background. I'm the one watching the door so they don't have to.

---

## How Client Onboarding Works

Signing a Client and actually protecting them should happen almost back to back — we keep things streamlined around here:

1. **Add the Client** — From the Control Room I hit **+ Add Client** and punch in their name, email, business, and industry.
2. **They get set up automatically** — The system spins up their account, generates their own unique API key, and emails them a one-time link to set their own password.
3. **Put my eyes on their place** — I drop a small snippet of code (already stamped with their key) into their website or app. From then on it quietly forwards security events to me.
4. **Everything comes in tagged to them** — Every event hits the `/api/ingest` door, gets checked against their key, and is filed under their account only.
5. **I work it, they get the Clipboard** — My analyst engine turns those events into incident reports. The Client logs in and sees the write-up on their place — and nothing else.

> **🗣️ Real Talk —** Signing a new Client is like agreeing to work a new venue's door. I get them set up in about five minutes, and they walk away with their own private pass — that API key — that stamps everything coming from their place as theirs, so I never mix up one Client's trouble with another's. After that, their system taps me on the shoulder whenever something happens, I handle it, and they log in to see the write-up on their own place. No Client ever sees another Client's business. That wall NEVER comes down.

---

## What's Live Today vs. Roadmap

I draw a hard line between what works right NOW and what's still on the drawing board. A Security Company that oversells is one nobody should trust, and I'm not about to be that.

### ✅ Model A — App Security Monitoring (LIVE)
A Client drops a small snippet into their website or app, and it starts forwarding security events to me — failed logins, injection attempts, someone poking around trying to find valid usernames, that kind of thing. I turn those into real incident reports the Client can actually use. This works TODAY, and I can sell it right now to any business with a web presence — a shop, a booking system, a POS with a login.

### 🚧 Model B — Full Infrastructure Monitoring (ROADMAP)
Watching a Client's whole setup — their servers, their network, not just their website — by installing a lightweight collector agent that ships all their system logs back to me. I've deliberately parked this until I've got 2–3 paying Model A Clients telling me it's worth building. The heavy lift is that agent; the rest is groundwork I've already laid.

> **🗣️ Real Talk —** Right now I can protect the part of a Client's business that lives on the internet — their website, their apps — and that on its own is a real service worth paying for. The bigger version, where I'm watching their whole shop floor and every back room, is the next chapter. I'm not building it on a hunch — I'll build it the day a paying Client tells me they need it. I'd rather promise small and deliver big than the other way around.

---

## Key Features

### Security Operations
- **Live SIEM feed** with severity bucketing (Critical / High / Medium / Low), multi-source filtering, multi-column sort, and 15-second auto-refresh
- **SPL-lite query engine** — write Splunk-style queries (`severity=HIGH | stats count by src_ip | sort -count`) against the live event store
- **MITRE ATT&CK integration** — findings mapped to attacker techniques; each links to tactics, detection guidance, and remediation steps
- **Incident response playbooks** — five-phase response guides (ransomware, phishing/BEC, data breach, account compromise, insider threat) in both technical (YAML) and plain-language versions
- **Automated threat simulation** — generates realistic Windows Event, firewall, and syslog events for training and demos

> **🗣️ Real Talk —** The SIEM is the metal detector — every bit of a Client's activity walks through it, and it goes off on the dangerous stuff. The query engine is me being able to rewind the tape and ask a pointed question, like "show me every failed login from this one address." MITRE ATT&CK is the industry's rap sheet on how attackers actually operate, so the moment I see something I already know what it's trying to pull. And the response playbooks are my "if this, do that" — written once for me, and once in plain language a business owner can follow on their worst day.

### Compliance
- **PCI DSS 4.0** auto-assessment against live scan findings — 12 requirements scored automatically
- **10 industry frameworks** — Cannabis (METRC), Healthcare (HIPAA), Financial (GLBA/SOX), Legal, Retail, Hospitality, Real Estate, Construction, Non-profit, General
- Per-client industry assignment; analysts can preview any framework

> **🗣️ Real Talk —** Regulated businesses — dispensaries, clinics, law firms — have rules they've got to follow or they get hit with fines. This checks a Client against the exact rulebook for their industry and shows them where they stand. It turns a scary phrase like "PCI DSS 4.0" into a plain checklist they can actually work through.

### Client Management
- **One-click onboarding** — create a Client, auto-issue their API key, and send a password-setup link in a single step
- **Three-role system** — Analyst (full ops), Client (their reports only), Demo (isolated sandbox showcase)
- **Client reports portal** with status workflow (New → Reviewing → Escalated → Closed)
- **Analyst notes** with discipline tracking (a "notes-before-triage" metric that keeps my investigation honest)
- **Weekly digest emails** via Resend

> **🗣️ Real Talk —** This is everything I need to run Clients as a business, not just show off a piece of tech. I can bring someone on in minutes, keep every Client's data walled off from every other Client, and even hand a prospect a demo login that lets them poke around a real-looking dashboard without ever touching a live Client's data.

### Analyst Experience
- **Live Ops / Study Mode toggle** — one click strips all educational scaffolding for a clean professional view, or surfaces full CISSP exam context throughout the UI
- **XP + level system** — resolving findings, completing training, and reading MITRE detail pages all earn XP
- **Scorecard** — tracks triage speed, escalation rate, and investigation discipline

> **🗣️ Real Talk —** I built this to make me sharper every time I use it. It quietly clocks how fast and disciplined I am on a case, and doubles as my CISSP exam prep — so running the shop and levelling up my own credentials happen in the same motion.

---

## Security & Data Isolation

- **Session-based authentication** with bcrypt password hashing
- **TOTP two-factor authentication (2FA)** with QR-code setup (Google Authenticator compatible)
- **CSRF protection** on every state-changing form (Flask-WTF)
- **Adjustable login throttle** — analyst-tunable rate limit (Normal / Elevated / Lockdown) that can be tightened live during a brute-force attempt, with every throttled attempt logged to the SIEM
- **Per-client data isolation** — every client-facing query is scoped by `owner_id`; a Client can only ever see their own reports, events, and findings (audited, no cross-client leakage)
- **Demo sandbox** — the demo account sees only its own seeded data and is blocked from modifying any real Client's records
- **One-time, time-limited setup and reset tokens** for password flows

> **🗣️ Real Talk —** I run a Security Company, so the platform itself has to be locked down tighter than anything it protects. Every Client's data sits behind its own locked door — I've checked every one of them, and not a single one opens into someone else's room. If somebody tries to force a login, I can tighten the lock with one click and watch every attempt light up my feed. And the demo I show prospects is a sealed sandbox — they can push every button in the place without ever touching a real Client.

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

> **🗣️ Real Talk —** I built this on boring, proven tools on purpose — Python and Flask are the workhorses of the web, and I talk to the database with my own hand-written queries so there's no black box hiding bugs from me. In production it runs on Railway with a proper PostgreSQL database behind it. The AI that writes reports runs free on my own machine while I build, and hands off to Claude in the cloud once it's live.

---

## Architecture

```
        A Client's website / app
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

> **🗣️ Real Talk —** Follow the arrows: a Client's website sends its security events up top, they land in a locked, labelled inbox at the door (`/api/ingest`), and from there everything fans out into the tools I use to make sense of it. The collectors along the bottom are how I keep an eye on my own setup today — and they're the groundwork for watching a Client's whole network tomorrow.

---

## Roles

| Role | Access |
|------|--------|
| `analyst` | Full platform — SIEM, SPL, compliance, training, CISSP, all client reports |
| `client` | Their own reports portal + compliance dashboard, nothing else |
| `demo` | Isolated sandbox — a realistic showcase populated with fake data only |

> **🗣️ Real Talk —** Three kinds of logins: me, and I see everything. A Client, who only ever sees their own place. And a demo login I can safely hand a prospect — it looks fully live, but it's a sealed sandbox with no real data anywhere in it.

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

> **🗣️ Real Talk —** To run it on your own machine: grab the code, install the pieces it needs, and start it up — the database builds itself. The secrets like API keys are never baked into the code; they get handed in separately when it runs, so nothing sensitive ever ends up on GitHub.
