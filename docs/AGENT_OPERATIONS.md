# Agent Operations — Boundry.AI

How Jason Morgan runs Cursor skills day-to-day for Boundry.AI revenue and client delivery.

---

## Quick start

1. Open this repo in Cursor
2. Ensure Flask + Ollama running (`C:\Dev\launch-boundry-ai.bat`)
3. Start a skill with `@` or natural language:

```
@weekly_siem_report_skill for client GreenLeaf — report date 2026-05-27
```

```
Run client onboarding for username acme_corp, scope siem, contact owner@acme.example
```

```
Triage finding 42 from SIEM — severity CRITICAL
```

The rule `.cursor/rules/boundry-skills.mdc` tells the agent which skill file to load.

---

## Skill files

| Skill | File | Money priority |
|-------|------|----------------|
| Weekly SIEM Report | `agent_skills/weekly_siem_report_skill.md` | **Path A — run first** |
| Client Onboarding | `agent_skills/client_onboarding_skill.md` | Path B foundation |
| New Finding Triage | `agent_skills/new_finding_triage_skill.md` | Path B — protects retainers |

Meta:
- `agent_skills/__how_to_use_step_skills.md` — CONCEPT → EDIT → REVISION_COMPLETE → TASK_COMPLETE loop
- `agent_skills/__how_to_take_notes.md` — progress file format

---

## Progress files

**Location:** `agent_tasks/`

| Skill | Pattern |
|-------|---------|
| Weekly report | `weekly_siem_report_<client>_<YYYY-MM-DD>_progress.md` |
| Onboarding | `client_onboarding_<client>_progress.md` |
| Triage | `new_finding_triage_<finding_id>_progress.md` |

Progress files are **gitignored** (except `agent_tasks/README.md`). They are the source of truth — not chat history.

---

## Resume after context reset

Cursor lost the thread? Say:

```
Read agent_tasks/weekly_siem_report_greenleaf_2026-05-27_progress.md and continue from "What remains".
```

Or:

```
@boundry-skills resume weekly SIEM report for GreenLeaf
```

Agent must re-read the skill file + progress file before continuing.

---

## The loop (every skill)

```
CONCEPT  → read skill + progress, confirm inputs
EDIT     → one chunk of work, update progress
REVISION_COMPLETE → run verification checklist in skill
TASK_COMPLETE → handoff to Jason (email, Stripe, next date)
```

Never skip CONCEPT. Re-read the skill every loop.

---

## Revenue workflow

```
Audit (one-time)  →  Weekly SIEM Report  →  Stripe subscription
     ↑                        ↑                      ↑
client_onboarding      weekly_siem_report_skill    Stripe MCP
     skill                      skill             (or Dashboard)
```

### Path A — money this week

1. Pick first retainer client (or demo client for dry run)
2. Run `@weekly_siem_report_skill` — 7-day pull, AI summary, markdown report
3. Email report to client contact
4. Verify/create Stripe subscription (`docs/MCP_SETUP.md`)
5. Log next report date (+7 days) in Notion CRM when connected

### Path B — foundation (between reports)

- Run `client_onboarding_skill` for each new signed client
- Run `new_finding_triage_skill` on every CRITICAL/HIGH finding same day

---

## What Jason does manually (for now)

| Task | Why |
|------|-----|
| Stripe OAuth on first MCP use | Cursor + Stripe connection |
| Send welcome / report emails | Until transactional email automated |
| Create client via `/register` | No admin UI yet |
| Set `SECRET_KEY`, `GMAIL_APP_PASSWORD`, VPN kill switch | Pre-client checklist |
| Slack bot setup | Optional alerts MCP |

---

## Artifacts output

| Type | Location |
|------|----------|
| Progress files | `agent_tasks/*_progress.md` |
| Weekly reports | `docs/reports/weekly_siem_<client>_<date>.md` |
| Incident reports (agent) | DB `reports` table + `/reports/<id>/pdf` |
| Stripe IDs | Progress file handoff section |

---

## MCP reference

See `docs/MCP_SETUP.md` for Stripe, Notion, Slack, Cloudflare portal setup.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| SIEM API returns login redirect | Log in as analyst at `/login` first |
| AI triage 503 | Start Ollama: `ollama serve` |
| Empty 7-day events | Check `siem_collector.py` threads, visit `/siem` |
| Stripe step BLOCKED | Complete MCP OAuth — see MCP_SETUP.md |
| Skill edits app.py | Stop — skills should not modify production code |

---

## Related docs

- `.cursorrules` — full Boundry.AI project context
- `docs/MCP_SETUP.md` — MCP wiring
- `.cursor/rules/boundry-skills.mdc` — auto-attach triggers
