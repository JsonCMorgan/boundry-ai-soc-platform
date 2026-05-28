# Boundry.AI — SOC Operations Platform

I'm building Boundry.AI as a cybersecurity services company targeting small-to-medium businesses in regulated industries — the dispensaries, medical practices, and law firms that need real security monitoring but can't get near an enterprise contract. This platform is the operational tool I'm building to run it.

---

## Platform Overview

| Module | Description |
|--------|-------------|
| 🖥 **Control Room** | Analyst HQ — live threat posture, VPN status, XP-based skill tracking |
| 📡 **SIEM** | Real-time event feed from Windows Event Log, firewall, syslog, and app sources |
| 🔎 **SPL Query Engine** | Splunk Processing Language interface over SQLite — filter, aggregate, export |
| 📋 **Compliance Dashboard** | PCI DSS 4.0 auto-assessment + 10 industry frameworks (HIPAA, GLBA, METRC, etc.) |
| 🛡 **Reports** | Client-facing findings portal with triage workflow, notes, and escalation tracking |
| 🎓 **SOC Training** | MITRE ATT&CK scenario lab with XP rewards and performance scorecard |
| 📘 **CISSP Study Hub** | 8-domain exam prep woven throughout the analyst workflow |

---

## Key Features

### Security Operations
- **Live SIEM feed** with severity bucketing (Critical / High / Medium / Low), multi-source filtering, and 15-second auto-refresh
- **SPL-lite query engine** — write Splunk-style queries (`severity=HIGH | stats count by src_ip | sort -count`) against the live event store
- **MITRE ATT&CK integration** — findings mapped to techniques; each links to tactics, detection guidance, and remediation steps
- **Automated threat simulation** — generates realistic Windows Event, firewall, and syslog events for training and demo

### Compliance
- **PCI DSS 4.0** auto-assessment against live scan findings — 12 requirements scored automatically
- **10 industry frameworks** — Cannabis (METRC), Healthcare (HIPAA), Financial (GLBA/SOX), Legal, Retail, Hospitality, Real Estate, Construction, Non-profit, General
- Per-client industry assignment; analysts can preview any framework

### Client Management
- Three-role system: **Analyst** (full ops), **Client** (reports portal), **Demo** (guided showcase)
- Client-facing reports portal with status workflow (New → Reviewing → Escalated → Closed)
- Analyst notes with discipline tracking (notes-before-triage metric)
- Weekly digest emails via Resend

### Analyst Experience
- **Live Ops / Study Mode toggle** — one click strips all educational scaffolding for a clean professional view, or surfaces full CISSP exam context throughout the UI
- **XP + level system** — resolving findings, completing training, and reading MITRE detail pages all earn XP
- **Scorecard** — tracks triage speed, escalation rate, and investigation discipline

### Security & Auth
- Session-based authentication with bcrypt password hashing
- TOTP-based two-factor authentication (2FA) with QR code setup
- CSRF protection on all state-changing forms
- Rate limiting on login and sensitive endpoints
- Emergency reset flow with signed time-limited tokens

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 · Flask |
| Database | SQLite (via Flask-SQLAlchemy) |
| Auth | Flask-Login · PyOTP (TOTP 2FA) · bcrypt |
| Email | Resend API |
| Frontend | Jinja2 · Vanilla JS · CSS custom properties |
| Deployment | Railway |
| Log ingestion | Custom Splunk forwarder · Windows Event collector |

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Boundry.AI                      │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Control  │  │   SIEM   │  │  Compliance   │  │
│  │  Room    │  │  + SPL   │  │  Dashboard    │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Reports  │  │ Training │  │ CISSP Study   │  │
│  │  Portal  │  │   Lab    │  │     Hub       │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│              Flask + SQLite                      │
└─────────────────────────────────────────────────┘
         ↑                        ↑
   Splunk Forwarder         Windows Event
   Syslog Collector         Log Collector
```

---

## Roles

| Role | Access |
|------|--------|
| `analyst` | Full platform — SIEM, SPL, compliance, training, CISSP, client reports |
| `client` | Reports portal + compliance dashboard for their account only |
| `demo` | Guided showcase view with tour banners |

---

## Local Setup

```bash
git clone https://github.com/JsonCMorgan/boundry-ai-soc-platform.git
cd boundry-ai-soc-platform
pip install -r requirements.txt

# Environment variables
export SECRET_KEY=your-secret-key
export RESEND_API_KEY=your-resend-key   # optional — for email alerts
export APP_URL=http://localhost:5000

python app.py
```

The app auto-creates the SQLite database on first run.

---

## Deployment

Deployed on [Railway](https://railway.app). Environment variables managed via Railway dashboard. SQLite database persists via Railway volume.

---

## Why I Built This

I wanted to train for real-world scenarios, so I started thinking about who would actually need my services and what cybersecurity looks like from their side of the table.

My background is in physical security — almost a decade working the door at bars and entertainment venues. A bouncer's job and a SOC analyst's job are more alike than people realise. You're reading the room, spotting the threat before it becomes an incident, deciding in real time whether to escalate or handle it yourself, and at the end of the night the establishment is still standing. Same thought process, but now I have real tools to assist instead of working with just my hands and wits.

When I made the transition to cybersecurity I kept seeing the same gap. Governments and regulators are now holding companies accountable for how they protect their data — and rightfully so, after watching corporation after corporation absorb a breach, pay out millions, and move on. But the small business owner around the corner — the dispensary, the medical clinic, the law firm — they don't have a security team. Most of them don't know what ransomware would actually cost them until it's too late to find out. They're running a bar with no bouncer on the door and they don't even know it.

I built this platform to be the thing that changes that equation. One analyst, multiple clients, real monitoring — without needing an enterprise budget or an enterprise team to run it. If I can give a small business the same visibility that a large one pays a fortune for, that feels like the right use of what I'm learning.

I'm also working through my CISSP while building this, so I wired the exam domains directly into the platform. Every MITRE technique, every compliance control, every incident type connects back to a domain. Turns out the best way to learn something is to build it.

---

*Jason Morgan · [Boundry.AI](https://boundry.ai)*
