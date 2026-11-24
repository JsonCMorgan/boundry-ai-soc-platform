# Boundry.AI — Implementation Plan (living)

**Source of truth for product intent:** [`docs/PRD.md`](PRD.md)  
**How agents use this file:** see `.cursor/rules/boundry-context-work.mdc`  
**Last updated:** 2026-11-22

Work **one stage at a time**. Prefer Career/Sec+ when they conflict with Live (PRD Q7). Do not invent features outside the PRD Won’t list.

---

## Decision filter (gate every addition)

Ship only if **all** are true:

1. Maps to a PRD Must/Should, a roadmap **G#**, or a Sec+ SY0-801 objective  
2. Does not violate Won’ts (no false Real/Practice, no cloud client AI, no tiers/demo lock before Roy)  
3. Has a one-line acceptance check (smoke or Given/When/Then)  
4. Fits the current stage below  

Defer: new cert tracks before Sec+ pass, vendor tenants without connectors, GEO-in-repo, full MDR claims, second-machine syslog.

Known defects: check [`docs/BUGS.md`](BUGS.md) before “fixing.”

---

## Locked constraints (do not re-decide in chat)

- Flask + SQLite local / Postgres via `DATABASE_URL`; `db_*` + `{PH}`
- Ollama first; client/ops data **never leaves the machine**
- Career labs may simulate; Live labels **Real** vs **Practice**
- No CompTIA/ISC² dumps; outlines as coverage maps only
- Intentional training vulns stay labeled; ops paths stay secured

---

## Stage 0 — Context engineering (this workflow)

- [x] Living PRD (`docs/PRD.md`)
- [x] Implementation plan (this file)
- [x] Project structure snapshot (`docs/PROJECT_STRUCTURE.md`)
- [x] Bug log (`docs/BUGS.md`)
- [x] Always-on work rule (`.cursor/rules/boundry-context-work.mdc`)
- [x] Decision filter documented (goal-aligned builds plan)

---

## Stage 1 — Sec+ hire foundation (Career default)

**Goal:** Pass Sec+ in Hub; keep tutor voice (define-before-use).

**Exam version (Jason, 2026):** **SY0-701** is the study north star while the licensed Messer pack is SY0-701. Revisit **SY0-801** spine/coverage when Messer (or Jason) has 801 course materials.

- [x] SY0-801 matrix coverage 100% mapped (`docs/secplus-objective-coverage.md`) — future pass / gap check when 801 content lands
- [x] Depth pass on 2.3 / 2.4 (+ warm 2.1 / 2.6 practice); smoke + MCQ lint green
- [x] Job Skills board exists (`/career/skills`)
- [ ] Keep deepening as exam date nears

**Done when:** Jason can study end-to-end in `/career/secplus` with confidence toward exam day.

---

## Stage 2 — Job Skills board

- [x] `/career/skills` — proficient vs developing vs recommended adjacent
- [x] Career hub surfaces study streak + Job Skills CTA
- [ ] Monthly glance: proficient count ↑, recommended skills getting reps

---

## Stage 2b — Memory retention (Boundry Retention Layer)

**Goal:** Spaced recall after Prove/Help-me/labs; local FSRS; no cloud sync.

- [x] `memory_retention.py` + `retention_*` tables + py-fsrs
- [x] `/career/review` session + Career hub due widget
- [x] Sec+ prove/help/terms/teach-back/72h mini-quiz enroll
- [x] SPL / KQL / Net prove + net/logs flashcard enroll
- [x] Intel/vuln/shift/training enroll + Review Mix interleaving
- [x] PRD metrics (weekly reviews, due backlog), profile stats, CSV export
- [x] `docs/MEMORY_RETENTION_UX.md` + tutor rule + `tests/test_memory_retention.py`
- [ ] Linux track: call `enroll_items` when `/career/linux` ships

**Jason personal (not a client Must):** Professor Messer private layer — `content/private/messer/`, `ENABLE_MESSER_LAYER=1`, ingest via `tools/messer_sync_all.py`, policy in `docs/PRIVATE_STUDY_SOURCES.md`. Hybrid Help from notes: `tools/messer_generate_notes_quizzes.py` + audit `tools/messer_notes_quiz_audit.py`.

**Done when:** After any Sec+ Prove pass, analyst has cards due within 24–48h on `/career/review`.

---

## Stage 3 — Desk-ready practice loop

- [x] G14 handoff rubric on `/soc` end-of-shift (+ XP bonus ≥75)
- [x] Practice feed variety (client rotation, SLA race mix, extras)
- [x] G15 Comms Gym (`/career/comms`)
- [x] Lesson streaks visible on Career hub
- [ ] Interview Gym after Sec+ momentum, not instead of it
- [ ] Regular `/soc` Practice shifts (habit / metric)

---

## Stage 3b — Futureproof Job Skills (foundation → tomorrow → owner)

- [x] Job Skills era tags + Work next boost (`career_skills.py`)
- [x] G13 SOAR enrich→approve→contain Career drill (`/career/soar`)
- [x] G21 Autopilot Oversight Gym (`/career/oversight`)
- [x] G17 Tune-or-tolerate (`/career/tune`)
- [x] G16 ops metrics lesson + widget (`/career/metrics`)
- [x] G22 Practice-tenant automation policy (`/career/automation-policy`)
- [x] G18 Automation lite (safe local snippets) (`/career/automation`)
- [x] `/soc` timeline: agent-proposed vs human-approved labels (via Boundry Tickets)

## Stage 3c — Boundry Tickets (local ITSM-lite)

- [x] `ticket_no` (BT-YYYY-NNNN), priority, statuses new/working/waiting/escalated/closed
- [x] Escalate as living state + required note; close requires disposition
- [x] `soc_ticket_events` timeline (human / agent_proposed / system)
- [x] `/soc/tickets` list + filters; floor workspace wired
- [x] Single-analyst v1 (no multi-user assign)

---

## Stage 4 — Pre-client Live hardening (Must gate M1–M8)

See [`docs/PRE_CLIENT_HARDENING.md`](PRE_CLIENT_HARDENING.md).

- [ ] M1 SECRET_KEY env set (Jason host config; launch bat has FLASK_DEBUG=false)
- [x] M2 Client isolation foundation (`mssp_tenants` + `client_id` on findings/SIEM)
- [x] M3 Demo/client cannot reach ops/Career/SIEM/SOC (route guard)
- [ ] M4 Alert email path (`GMAIL_APP_PASSWORD`); local alternate documented in IR mini path
- [ ] M5 NordVPN kill switch ON (host setting; still OFF last check)
- [x] M6 Automated `app.db` backup script + BoundryAI-AppDbBackup task
- [x] M7 Privacy one-pager (`docs/PRIVACY_DATA_HANDLING.md`)
- [x] M8 Mini IR path (`docs/IR_MINI_PATH.md`)
- [x] SIEM Phase A FP (`docs/SIEM_FP_PHASE_A.md`): firewall background matrix, Quick FP templates, ingest tunes module; smoke `tools/_smoke_siem_fp_phase_a.py`

**Held for Roy:** service tiers, 5-minute demo script. Do not unlock until meetup.

---

## Stage 4b — Enterprise SecOps UX (Live bursts)

- [x] Unified SecOps shell (`_secops_layout.html`) + `soc_ioc_stub.py`
- [x] SIEM Log Activity tabs, saved searches, detections API (`siem_views.py`)
- [x] Mission Control `/soc/mission` (`mission_control.py`)
- [x] Case workspace API (timeline, entities, tasks, graph lite)
- [x] Control Room SecOps KPI + attention rail
- [x] SOAR workflow canvas (read-only) + 7d metrics
- [x] Docs `docs/ENTERPRISE_SECOPS_UX.md`; tests `tests/test_enterprise_secops.py`

---

## Stage 5 — Partnership / business packaging

- [ ] Meet Roy; decide merge shape
- [ ] Unlock tiers + demo bar in PRD
- [ ] Revisit Won’t list if needed

---

## Stage 6 — Security Portfolio Roadmap (mentor GitHub)

**Goal:** Ship Tier A–D items from `security_portfolio_roadmap` (agent store plan + Boundry HQ canvas). One repo or hygiene pass at a time; push after Jason confirms.

**Standalone vs MSSP:** See [`docs/PORTFOLIO_STANDALONE.md`](PORTFOLIO_STANDALONE.md) — recruiter-facing tools stay **separate repos**; flagship absorbs only Tier D + operator features (6b enrich, etc.).

**Progress (Jason, 2026-11-22):**

- [x] #1 Portfolio hygiene (`boundry-ai-soc-platform` pushed)
- [x] #2 Security Onion lab (GitHub)
- [x] #3 Juice Shop lab (GitHub)
- [x] #4 Phishing email analyzer ([phishing-email-analyzer](https://github.com/JsonCMorgan/phishing-email-analyzer))
- [ ] #5 IOC extractor (local `C:\Dev\ioc-extractor`; push when confirmed)
- [ ] #6–#19 per roadmap order (Jason picks next)
- [x] #7 Sigma pack (`soc-detection-rules`) — shipped earlier

**Done when:** Profile README promises match green, mentor-visible repos for chosen items.

---

## Stage 6b — SIEM on-demand IOC enrichment (after Stage 6)

**Goal:** Wire **analyst-triggered** enrichment into Live SIEM (local stub only in v1). Not background enrich on ingest.

**Spec:** [`docs/handoffs/SPEC-siem-on-demand-ioc-enrichment.md`](handoffs/SPEC-siem-on-demand-ioc-enrichment.md)

- [x] `POST /api/siem/enrich` (+ event_id parsing)
- [x] SIEM UI panel on selected event (`templates/siem.html`)
- [x] Docs + pytest smoke (`docs/SIEM_IOC_ENRICHMENT.md`)
- [ ] Demo: event → Enrich → stub verdict + defanged IOC in panel (Jason walkthrough)

**Started:** 2026-11-23 (Jason).

**Done when:** Acceptance checks in SPEC are checked; no outbound calls on default path.

---

## How to execute a stage in Cursor

1. Open a **new chat** for the stage (fresh context).
2. Point at PRD + this plan + `PROJECT_STRUCTURE` / `BUGS` as needed.
3. State lane (Career / Desk / Live burst), G# or M#, acceptance check.
4. Implement **one sub-chunk**; verify (smoke / test client).
5. Check off items here; log defects in `BUGS.md`.
6. Do not regenerate a second parallel PRD.
