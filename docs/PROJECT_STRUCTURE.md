# Boundry.AI — Project structure snapshot

**Purpose:** Keep agents oriented without dumping the whole repo into chat.  
**Update when:** major modules or top-level folders change.  
**Last updated:** 2026-11-22

```
MSSP/
├── app.py                 # Flask app (routes, init_db, XP, career, soc, …)
├── tenant_ops.py          # MSSP tenant slug helpers + SIEM filters
├── ingest_map.py          # /api/ingest → SIEM type mapping
├── client_product.py      # Onboard wizard, client status, privacy, M365 ingest route
├── boundry_deliverables.py # Weekly/monthly client deliverable builders
├── m365_ingest.py         # M365 audit JSON → SIEM (Phase 1)
├── ticket_fields.py       # Shared Ticket Field Console schema + grade + compose_note
├── *.py labs/engines      # siem_collector, siem_ingest_tunes, siem_fp_templates,
│                          # spl_engine, siem_views, mission_control, soc_ioc_stub,
│                          # vpn_monitor, soar_engine, career_lab, memory_retention, soc_lab, …
├── templates/             # Jinja pages (career_*, soc_floor, siem, cissp, …)
│                          # + _ticket_field_console.html (Career + Live Floor)
│                          # + _live_ops_shell.html (Floor / Tickets / Control Room chrome)
├── static/                # game.js, glossary.js, visuals
├── docs/
│   ├── PRD.md             # Product north star + MoSCoW
│   ├── IMPLEMENTATION_PLAN.md
│   ├── PROJECT_STRUCTURE.md  (this file)
│   ├── BUGS.md
│   ├── soc-l1-skills-roadmap.md
│   ├── secplus-objective-coverage.md
│   ├── net-for-soc-outline.md
│   ├── SIEM_FP_PHASE_A.md
│   ├── GITHUB_INDUSTRY_AUDIT.md      # GitHub vs industry standards (rubric + roadmap)
│   ├── PORTFOLIO_VERIFICATION_GUIDE.md
│   ├── GITHUB_AUDIT_QUARTERLY_CHECKLIST.md
│   └── …
├── .cursor/rules/         # tutor-professor-voice, boundry-skills, boundry-context-work
├── agent_skills/          # Boundry ops skills (weekly report, onboarding, triage)
├── tools/                 # Content generators, smokes, audits (not runtime)
└── app.db                 # Local SQLite state
```

## Surface map

| Surface | Entry | Notes |
|---------|-------|-------|
| HQ | `/control-room` | Ops overview |
| Analyst floor | `/soc` | MSSP workbench: dense queue, fielded BT tickets, work notes |
| Ticket history | `/soc/tickets` | Ops table queue for BT tickets (local ITSM-lite) |
| Control Room HQ | `/control-room` | HQ Attention rail + KPIs; Tools accordion; Live Ops hides MITRE encyclopedia |
| Futureproof Career | `/career/soar` `/oversight` `/tune` `/metrics` `/automation` `/automation-policy` | Tomorrow + owner Job Skills drills; SOAR/Shift use Ticket Field Console |
| Sentinel lab | `/career/sentinel` | 13 authored cases; seed randomizes surface fields |
| SIEM | `/siem`, `/siem/query` | Log Activity tabs (stream/group/detections); saved searches; stat filters; triage drawer → tickets |
| Mission Control | `/soc/mission` | Unified findings + tickets + SOAR queue |
| SecOps shell | `_secops_layout.html` | Left nav on Control Room, SIEM, SOC, SOAR |
| Career hub | `/career` | Tracks, drills, gates, Review due widget |
| Daily Review | `/career/review` | FSRS spaced queue (`memory_retention.py`) |
| Job Skills | `/career/skills` | Proficient / adjacent growth |
| Sec+ | `/career/secplus` | Primary cert this phase |
| Comms Gym | `/career/comms` | G15 stakeholder notes |
| Labs | `/career/{email,edr,logs,intel,net,vuln,sentinel,entra,spl,kql,interview,comms}` | Simulated |
| CISSP | `/cissp` | Deeper / later after Sec+ |
| Pre-client | `docs/PRE_CLIENT_HARDENING.md` | M1–M8 gate |
| Client status | `/client/status` | Monitoring heartbeat (client role) |
| Onboard wizard | `/analyst/onboard` | Analyst client onboarding |
| Privacy | `/privacy` | M7 one-pager in-app |
| M365 ingest | `POST /api/m365/ingest` | Phase-1 audit JSON |
| Monthly summary | `POST /cron/monthly-summary` | Per-client report rows |

## Rules of placement

- New Career curriculum → `*_learn.py` / `*_lessons.py` + `templates/career_*`
- New Live ops → prefer `soc_lab.py` / SIEM paths; label Real vs Practice
- Product decisions → update `docs/PRD.md` first, then this plan
- Agent ops (client delivery) → `agent_skills/`, not Career Hub
