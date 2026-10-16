# Boundry.AI — Product Requirements Document (Living)

**Status:** Draft v0.4a (Q1–Q15 answered; Job Skills metric; demo bar held for Roy)  
**Owners:** Jason (product/tech; sole Must-changer); Peta (GTM where noted); Roy (risk-assessment partnership, exploratory)  
**Last updated:** 2026-10-11  
**Style:** Lean living PRD. Short enough to read in one sitting. Links out for detail. Update when decisions change.

---

## How we keep this PRD effective

Research-backed rules for this file (lean PRD practice):

1. **Problem first.** If we cannot state the problem and evidence, we are not ready to add a Must requirement.
2. **One north-star line.** What Boundry must be true for this quarter.
3. **Testable requirements.** Prefer “Given / When / Then” acceptance over vague wish lists.
4. **MoSCoW priorities.** Must / Should / Could / Won’t for the current phase.
5. **Explicit non-goals.** Name what we are not building so scope stays honest.
6. **Team’s call.** Implementation details stay out unless they are hard constraints (privacy, offline-first, Ollama-first).
7. **Metrics with baselines.** Success is measurable, not vibes.
8. **Open questions with owners.** Unowned questions become blockers.
9. **Link, don’t paste.** Roadmaps, exam outlines, and feature specs live in sibling docs.
10. **Changelog at the bottom.** Living doc, not a frozen PDF.

**Sibling docs (not duplicated here):**
- `.cursorrules` — engineering conventions + pre-client checklist  
- `docs/BOUNDRY_AI_SERVICE.md` — client-facing service tiers (pricing hold until Roy meetup)  
- `docs/soc-l1-skills-roadmap.md` — Career Hub skill gaps  
- `docs/secplus-objective-coverage.md` — Sec+ SY0-801 coverage  
- `docs/net-for-soc-outline.md` — Net-for-SOC lesson outline  
- `docs/conference-cursor-briefing.md` — conference / hire talk track  
- `docs/IMPLEMENTATION_PLAN.md` — staged build checklist (context engineering)  
- `docs/PROJECT_STRUCTURE.md` — repo / route snapshot  
- `docs/BUGS.md` — known defects before “fixing”  
- `docs/PRE_CLIENT_HARDENING.md` — M1–M8 go-live checklist  
- `docs/PRIVACY_DATA_HANDLING.md` — M7 privacy one-pager  
- `docs/IR_MINI_PATH.md` — M8 mini IR + M4 local alert alternate  

**Held for Roy (do not build yet):** service tier prices/lock, fixed 5-minute demo script.

---

## 1. One-liner (north star)

**Current phase:** Boundry.AI is Jason’s personal SOC training gym and hardened local command center. Career/cert (Sec+ first) wins build time. Live stays real and labeled; Practice clients are enough for drills. Target future clients: general SMB/SaaS and personal-network monitoring. Client/ops data never leaves the machine. Service tiers and demo script wait on Roy. Success path: pass Sec+ → feel desk-ready → get interviews.

**Job Skills eras (futureproof):** foundation (classic L1) remains hire baseline; tomorrow (SOAR chains, AI/agent oversight, tune-or-tolerate) and owner (ops metrics, per-tenant automation policy) steer Work next after foundation greens. Not a claim of commercial AI-SOC or 24×7 MDR.

**2026 success bar:** Platform is functional and hardened, with the functionality needed to succeed in the industry, and Jason is prepared and well trained for workforce work and self-employment in cyber.

---

## 2. Problem

**Primary (Jason / hire path):** Deliberate practice across real analyst workflows, not dump-based cert grind. Hireability is the proxy for “can do the job for Boundry too.” Career/cert preference hedges while the business is not running.

**Secondary (business, near-term hold):** Long-term market is general SMB/SaaS and personal-network monitoring. Packaging, pricing, and demo bar deferred until Roy returns.

**Evidence / assumptions:** Skills roadmap + JD patterns; MSSP pre-client practices (secrets, isolation, end-to-end alert path, IR/notification, backups); Roy meetup in ~couple of weeks.

**Why now:** Train before/while partnership talks; harden Boundry through 2026.

---

## 3. Users and jobs

| Persona | Priority | Job to be done | Primary surfaces |
|---------|----------|----------------|------------------|
| Jason (analyst / builder) | **#1 this phase** | Pass Sec+; feel desk-ready; then interviews; harden Live for self-use / future clients | Career Hub, `/soc`, SIEM, Control Room, labs |
| Roy (partner, exploratory) | Later | Merge exploration; unlock tiers + demo decisions | TBD after meetup |
| Peta (GTM) | Secondary | Explain Boundry when client push resumes | Service doc, reports/PDF |
| SMB / SaaS + personal-net client | Deferred | Monitoring + plain-English incidents | Reports, alerts, `/soc` |
| Demo viewer | Held | 5-min walkthrough (content TBD with Roy) | `/demo`, Control Room, `/soc` |

---

## 4. Product pillars

| Pillar | Intent | Today (summary) |
|--------|--------|-----------------|
| **Career / train** | Hire-aligned tutor; **Sec+ SY0-801 first** (Q10) | Default build preference (Q7); CISSP after Sec+ |
| **Live ops** | Real monitoring + Practice clients | `/soc` hybrid; SIEM; VPN; reports; Must-before-client gate (Q9) |
| **Business** | Retainer packaging | Tiers + demo bar held for Roy (Q5, Q13) |

Hard constraints:
- **Privacy (Q6):** never leave the machine for client/ops AI. Ollama only.  
- No CompTIA/ISC² dumps; outlines as coverage maps only.  
- **Honesty (Q12):** no false capability claims; Practice must never look like Real; intentional training vulns stay labeled and out of client/ops paths.  
- Real ops paths stay secured.

---

## 5. Success metrics (monthly — Q14)

| Metric | Meaning | Baseline | Target | Window | Source |
|--------|---------|----------|--------|--------|--------|
| **Lesson streaks** | Days with meaningful Career/Sec+ study activity | TBD (set after 1 week of logging) | Keep streak alive; raise bar after baseline | Monthly | Career / Sec+ progress |
| **Shift completions** | Finished `/soc` shifts with handoff done | TBD | Rising completions; quality over volume | Monthly | `/soc` shift sessions |
| **Job Skills** | Skills **proficient** from training signals, plus **Work next** (adjacent skills that pair with strengths). Not job-application counts. | TBD after first `/career/skills` glance | Proficient count ↑; recommended skills getting reps | Monthly | `/career/skills` board |

Career success order (Q11): **(1) pass Sec+ → (2) feel ready on a real desk → (3) get interviews.**

---

## 6. Scope — current phase

**Phase label:** Personal SOC Training Gym + platform hardening (client acquisition, tiers, demo script paused for Roy).

### Must
- Career/cert wins build conflicts; **Sec+ SY0-801 only** until passed, then next cert decided (Q7, Q10).
- Practice clients on `/soc` for field-realistic drills (Q8).
- Privacy: never leave the machine (Q6).
- Honesty: no false info; Real vs Practice always clear; training vulns labeled (Q12).
- **Must before first paying client (Q9 — recommended from current gaps + industry practice):** see §6.1.

### Should
- Deepen Practice feed quality before physical second feeds.
- Crash recovery / auto-restart for Flask.
- Open-port review on Boundry host.
- Revisit tiers + demo with Roy.
- Boundry Tickets ITSM-lite on `/soc` (local ticket_no, states, escalate, timeline, history). Single-analyst v1.

### Could
- Second-machine / syslog later.
- VirusTotal / Shodan / Splunk HEC when needed (not blocking first personal-net or first SMB if core path works).
- Multi-user assign / queue for Boundry Tickets after single-analyst path is solid.

### Won’t (this phase / next year — Q12 draft)
- Present Practice data or training vulns as production client truth.  
- Ship client/ops paths that stay intentionally vulnerable.  
- Claim capabilities Boundry does not have.  
- Put GEO/marketing platform inside this repo (stays in `peta-tools`).  
- Lock audit / $299 / $799 tiers or a fixed 5-min demo script until Roy (Q5, Q13).  
- Cloud AI for client/ops data (Q6).  
- Full MDR / 24×7 staffing claim, pen-test firm identity, or fake “we have Defender tenant” without real connectors.  
- Replacing Control Room with `/soc`.
- ServiceNow / Jira replacement or sync this phase (Boundry Tickets stays local ITSM-lite).

### 6.1 Must before first paying client (Q9 recommendation)

Grounded in: Boundry pre-client checklist + common MSSP/MSP go-live practice (secrets hygiene, client isolation, end-to-end detect→alert, IR/notification clarity, platform backups, host protection). Sources used: HailBytes MSSP onboarding checklists, MSP day-one baselines, Keeper MSSP secrets guidance, NDISAC MSP shopping themes (isolation, IR expectations).

| # | Must | Why | Boundry status today |
|---|------|-----|----------------------|
| M1 | Production `SECRET_KEY` + `FLASK_DEBUG` off | Session forgery / debug exposure = unusable as a trust product | Open in checklist |
| M2 | Client data isolation (decide + implement: `client_id` tags **or** DB-per-client) | Industry expectation: one client must not see another’s data | Not started |
| M3 | `/demo` (and any shared login) cannot see real client data | Demo leakage is a trust killer | Review still open |
| M4 | Alert path end-to-end (event → SIEM/finding/case → notify Jason) | MSSP checklists require tested detect→ticket/alert before go-live | Needs `GMAIL_APP_PASSWORD` + chain test, or documented local-only alternate |
| M5 | NordVPN kill switch on (ops host) | Protect the monitoring host on untrusted networks | Checklist: currently OFF |
| M6 | Automated `app.db` backup (daily, second drive) | Platform holds the evidence trail; backup is non-optional | Not automated |
| M7 | One-page privacy / data handling statement matching “never leave the machine” | Buyers and partners ask where data goes | Missing |
| M8 | Written mini IR path: what is an incident, who gets called, SLA for personal-net vs SMB | MSP shopping guides expect IR/notification clarity before access | Informal only |

**Not Must for first client (Should/Could):** Splunk HEC, VT/Shodan keys, polished 5-min demo (held for Roy), full MSA (pair with Roy), cannabis-only GTM.

**Build order suggestion while Career is default:** keep Sec+ as daily priority; knock out M1/M5 (config, hours) and M6 (small automation) in short Live hardening bursts; design M2/M3/M7/M8 before any real client data lands; do M4 before promising monitoring.

---

## 7. Requirements table

| ID | Priority | Requirement | Acceptance criteria |
|----|----------|-------------|---------------------|
| R1 | Must | Career wins build conflicts | Given Live vs Career conflict, When prioritizing, Then Career/cert ships first unless Jason overrides for a Live blocker |
| R2 | Must | Privacy on-machine | Given client or ops data, When AI is used, Then only local Ollama |
| R3 | Must | Practice clients sufficient | Given drill need, When on `/soc`, Then Practice + Real labels meet need without second-machine Must |
| R4 | Must | Sec+ first | Given cert work, When choosing curriculum, Then SY0-801 Sec+ until passed |
| R5 | Must | Honest product | Given any UI or demo, When showing data, Then Real vs Practice is explicit and no false capability claims |
| R6 | Must | Pre-client gate M1–M8 | Given first paying client, When go-live, Then §6.1 items are done |
| R7 | Held | Demo bar | TBD with Roy (Q13) |

---

## 8. Architecture constraints (team must respect)

- Flask command center, SQLite local / Postgres via `DATABASE_URL`  
- `db_*` helpers + `{PH}` placeholders  
- Operations vs Training nav; `/soc` = analyst floor; Control Room = HQ  
- Career labs may simulate; Live must label **Real** vs **Practice** clearly  
- AI for ops/client context: local Ollama only (Q6)

---

## 9. Risks

| Risk | Mitigation |
|------|------------|
| Scope sprawl | MoSCoW + Won’t list; Career default; Sec+ first |
| Privacy slip | Never-leave-machine; outline-only cert content |
| Live vs Career confusion | Clear labels; deep-links not fake tenants |
| Pre-client security gaps | §6.1 Must gate + `.cursorrules` checklist |
| Service-tier / demo drift | Explicit hold for Roy |
| False confidence / false claims | Q12 honesty rule |

---

## 10. Process

- **Who can change a Must:** Jason only (Q15).  
- **Revisit cadence:** monthly (recommended default; Jason can call an earlier pass after Roy meetup).  
- **Open holds:** service tiers (Q5), demo bar (Q13), finer “what Boundry is not” after Roy if needed.

---

## 11. Open questions / answered log

**Answered:**  
- Q1 — training gym now; Roy meetup soon  
- Q2 — Jason hire path #1  
- Q3 — 2026 functional + hardened + trained  
- Q4 — general SMB/SaaS **and** personal network  
- Q5 — tiers/pricing hold until Roy  
- Q6 — never leave the machine  
- Q7 — Career/cert wins build conflicts  
- Q8 — Practice clients enough for now  
- Q9 — Must-before-client = §6.1 (recommended)  
- Q10 — Sec+ first; then decide next  
- Q11 — pass Sec+ → desk-ready → interviews  
- Q12 — honesty + no unlabeled vulns / false info; broader “not MDR/pentest/GEO-in-repo” draft; refine with Roy if needed  
- Q13 — demo bar hold until Roy  
- Q14 — monthly: shift completions, lesson streaks, Job Skills (proficient + adjacent Work next)  
- Q15 — Jason only changes Musts; monthly revisit  

**Held for Roy:** Q5 detail, Q13 demo script, optional Q12 expansion.

---

## Changelog

| Date | Change |
|------|--------|
| 2026-10-11 | Initial lean PRD skeleton + research rules |
| 2026-10-11 | v0.2: Q1–Q3 |
| 2026-10-11 | v0.3: Q4–Q8 |
| 2026-10-11 | v0.4: Q9–Q15; Must-before-client §6.1 from checklist + MSSP practice; metrics defined; Sec+ first; honesty Won’ts |
| 2026-10-11 | v0.4a: Option C context docs + work rule; Job Skills metric + `/career/skills` (replaces hire-apps) |
| 2026-10-11 | v0.4b: Boundry Tickets ITSM-lite on `/soc` (Should); Won’t ServiceNow sync this phase |
