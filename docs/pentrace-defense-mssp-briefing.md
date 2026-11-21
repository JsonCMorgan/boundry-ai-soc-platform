# PenTrace Defense Mode — MSSP Context Briefing (Boundry.AI)

**Prepared for:** PenTrace game design (post–Mr. Cipher Defense Mode)  
**Source:** Boundry.AI MSSP command center + Career Hub practice patterns (fictional clients only)  
**Author context:** Jason Morgan, GTA — pre-revenue 2-person MSSP build, SMB focus  
**Redaction:** No real customer names, IPs, domains, or credentials. Example IPs use TEST-NET blocks.

---

## 1. MSSP snapshot (1 page)

### What Boundry does (today vs target)

| Capability | Status | Game relevance |
|------------|--------|----------------|
| **Continuous monitoring** (SIEM ingest, correlation, analyst review) | Built (local stack) | Core Defense Mode loop |
| **Weekly monitoring reports** | Skill-driven workflow | “Contract board” / mail deliverable |
| **One-time security audit** | Scanner + findings | Onboarding mission |
| **Incident response / containment** | Playbooks + SOAR (approve-gated); not 24/7 NOC yet | Escalation missions |
| **vCISO / compliance narrative** | Compliance dashboard (PCI, HIPAA, METRC, etc.) | Optional side quests |
| **MDR-style 24/7 follow-the-sun** | **Not yet** — aspirational | Game can simulate; label as “training shift” |

**Typical customer size:** **SMB** (10–200 employees). General professional services, SaaS, and local business networks. No single vertical locked for Boundry GTM.

**Boundry vs generic MSSP:** No dedicated L2/L3 bench yet. Jason = technical lead + builds the platform; operations are **analyst-first** with **local Ollama** for triage notes (no silent cloud on client data). Single-tenant DB today (multi-client tagging in progress); practice queue uses fictional tenants **Contoso**, **NorthPeak**, **Harbor**.

### Tier structure (roles)

| Role | Boundry name / reality | Owns |
|------|------------------------|------|
| **L1 SOC Analyst** | You (player in game) | Queue pick-up, SIEM search, first ticket note, disposition, SLA clock |
| **Senior / lead analyst** | “Jason” or **Lead** | Escalation approval, client email, contain/isolate decisions |
| **IR / containment** | Same person today | SOAR playbook approve step (`/soar`) |
| **Customer-facing** | Jason (+ partner for business) | Weekly report, retainer, scope boundary |
| **Client user** | `client` role in app | Read reports, integration page — not tier-1 triage |

### Day one vs 90 days (what we want analysts to *feel*)

| Day one | After ~90 days |
|---------|----------------|
| Overwhelmed by **noise**; fear of closing wrong | Pattern-match **spray vs brute force**, VPN FP vs real drop |
| Copy-paste SIEM search; unsure what matters | **SPL/KQL-shaped** queries with time bounds |
| Tickets without **MITRE** or **next action** | Every close has **disposition + one-line customer update** |
| Escalate everything | **Escalate vs contain vs FP** with evidence cited |

---

## 2. Intake and ticketing

### How work enters

| Channel | Boundry route / object | Typical payload |
|---------|------------------------|-----------------|
| **SIEM detection / correlation** | `system_findings` (scan_type=`siem`) | Rule name, severity, linked `siem_events` |
| **Live log stream** | `siem_events` (HIGH/CRITICAL) | Windows 4625, firewall, syslog, app auth |
| **Scanner / machine audit** | `system_findings` (scanner) | Misconfig, open port, weak control |
| **Practice / shift queue** | `soc_practice_events` | Multi-client tagged alerts |
| **Email / phone** | **Manual** (outside app today) | “User locked out” → becomes ticket context |
| **Weekly report trigger** | Scheduled (Path A revenue) | Not incident — separate workflow |

**Game mapping:** Mail = client note or internal handoff; contract board = client tag + SLA tier; incident timer = `sla_due_at` / shift `sla_minutes`.

### Ticket / case lifecycle (exact labels — Boundry Tickets)

**Ticket number format:** `BT-{YYYY}-{NNNN}` (e.g. `BT-2026-0042`)

**Case statuses** (`soc_cases.status`):

1. `new` — created, unassigned work started  
2. `open` — legacy alias still honored in queries  
3. `working` — analyst owns investigation  
4. `waiting` — blocked on client, change window, or lead approval  
5. `escalated` — IR lead / Jason engaged (`escalate_note` required)  
6. `closed` — terminal

**Disposition on close** (`disposition`):

- `true_positive` — malicious or policy violation confirmed; action taken or recommended  
- `false_positive` — benign, expected, or duplicate noise  
- `escalate` — cannot close at L1; handed off (may still be “open” until IR closes)

**Timeline events** (`soc_ticket_events`): `human` | `agent_proposed` | `system` — supports “fixer” / AI assist without auto-closing.

**Shift practice mirror** (`expected_disposition`): grader knows intended TP/FP/escalate.

### Severity / priority

**Event severity (SIEM):** `CRITICAL` → `HIGH` → `MEDIUM` → `LOW` → `INFO` (ordered).

**Priority mapping** (ticket): derived from severity (1 = hottest, 5 = coolest) via `priority_from_severity()`.

**How chosen in practice:**

- **Rule / correlation** sets initial severity  
- Analyst may **not** downgrade CRITICAL without note (game: lose points for silent downgrade)  
- **Client tier** (Gold/Silver) affects narrative pressure, not always numeric SLA in dev

**Generic MSSP difference:** Mature shops use PSA priority matrices; Boundry uses **severity + SLA minutes on shift card**.

### Escalation path

```
SIEM event / finding → Open BT ticket (L1) → enrich (IOC stub, SPL query)
        → disposition draft
        → if contain/isolate needed → Lead approve (SOAR gate)
        → if client notify → email / ticket note
        → close OR escalated → Jason / IR
```

**Ownership:**

| State | Owner |
|-------|--------|
| `new` / `working` | L1 analyst |
| `waiting` | Client or lead (clock still runs) |
| `escalated` | Lead / IR |
| `closed` | L1 with lead review on CRITICAL |

### What “done” means

- **FP:** Document *why* (change ticket, known scanner, Defender routine)  
- **TP:** Actions listed (block IP, reset creds, MFA enforced); IOC noted  
- **Escalate:** Handoff note; do **not** mark closed at L1  
- **Client retainer:** Weekly report still goes out even if no incidents (Path A)

**Not done:** “Looked at it” with empty `summary` / `next_action`.

---

## 3. Tools and data (generic names OK)

| Category | Boundry implementation | Analyst screens |
|----------|------------------------|-----------------|
| **SIEM** | Local `siem_events` + correlation → `system_findings` | `/siem` live stream, grouped, detections; `/siem/query` SPL-lite |
| **Command / posture** | Control Room | `/control-room` — VPN, clients, findings strip |
| **SOC queue** | Mission + floor | `/soc/mission`, `/soc` — BT tickets, shift |
| **SPL / hunting** | `spl_engine.py` | `/siem/query`, API `/api/siem/spl` |
| **EDR (training)** | Career sim, not live vendor | `/career/edr` |
| **Email security (training)** | Header lab | `/career/email` |
| **Firewall logs** | Tail `pfirewall.log` + ingest | SIEM source `firewall` |
| **Windows logs** | Security/System poll | `windows_event` (4624/4625/4720…) |
| **Identity** | Entra lab + SIEM auth | `/career/entra`, practice identity alerts |
| **VPN telemetry** | NordVPN file read | `vpn_monitor` — CRITICAL on unexpected drop |
| **Ticketing** | **Not ServiceNow** — `soc_cases` | Boundry Tickets `BT-…` |
| **SOAR** | Approve-gated playbooks | `/soar`, `/playbooks` |
| **Threat intel** | **Local stub** (no VT key required in lab) | `/career/intel`, `lookup_ioc` |
| **Splunk (optional)** | HEC forwarder silent until token set | Forward-only |
| **AI triage** | **Ollama first** | `POST /api/siem/findings/<id>/triage` → 4-bullet note |
| **PSA** | **Not integrated** — progress files + email | Real shop would be ConnectWise/Halo; game can fake |

**Automation split:**

- **Auto:** Ingest, correlation rule fires, SLA timer starts  
- **Human:** Disposition, contain, client comms, close  
- **Propose:** AI triage (`agent_proposed` timeline event); analyst edits  

---

## 4. A “normal shift” narrative (fictional)

**06:55** — Log into **Control Room**. VPN strip green for **NorthPeak (Silver)**. **Mission** shows three open items: INFO Defender scan (Contoso), HIGH failed logons (Contoso), CRITICAL spray pattern (NorthPeak).

**Decision 1 (fail point):** Pick INFO first because it’s “easy” → **SLA on CRITICAL slips**. Correct: sort by severity + SLA minutes.

**07:05** — Open **BT-2026-0103** from SIEM rule “Failed Logon Burst.” Run SPL: `severity=HIGH earliest=-1h | stats count by user, src_ip`. See 47× `jsmith` / `203.0.113.44`. No 4624 success. Enrich IP in intel stub → “known hostile, low confidence.”

**Decision 2:** Jump to isolate host — **out of scope** without lead. Correct: recommend **block src_ip**, **force password reset**, **confirm MFA**, note MITRE **T1110.001**.

**07:20** — Second queue item: VPN **LOW** “reconnect after drop.” Check change ticket **CHG-441** in detail text → **false_positive**, close with reference.

**07:35** — Client email in narrative: “NorthPeak owner asks if they were breached.” Draft reply: timeline, no success logons, actions taken, no evidence of compromise.

**08:00** — Handoff note for anything `escalated` or `waiting`. Shift metric: **2 closed**, **0 SLA breach**, **1 customer update sent**.

---

## 5. Investigation patterns (teachable)

### Phishing / BEC triage

| | |
|--|--|
| **Goal** | Decide phish vs legit; protect creds and payments |
| **Actions** | Parse headers (SPF/DKIM/DMARC); compare display name vs reply-to; check unusual wire/payment language |
| **Success** | Disposition + user guidance (don’t click, report, reset if clicked) |
| **Common mistakes** | Trusting “From: CEO” without auth results; mass-delete without ticket |

### Malware host alert

| | |
|--|--|
| **Goal** | Confirm execution vs PU P; scope host |
| **Actions** | EDR-style timeline; process tree; check 4688/Defender events in SIEM |
| **Success** | Escalate with isolate **request**; preserve evidence note |
| **Mistakes** | Isolate before approval; rebooting (loses RAM evidence) |

### Brute force / auth anomaly

| | |
|--|--|
| **Goal** | Spray vs targeted brute; find success (4624) |
| **Actions** | `4625` count by user/IP; same password many users = spray; one user many passwords = brute |
| **Success** | Block IP or IdP lockout policy cited; reset + MFA |
| **Mistakes** | Calling spray “brute force” in client comms; missing parallel success event |

### Lateral movement suspicion

| | |
|--|--|
| **Goal** | Prove or disprove east-west movement |
| **Actions** | 4624 type 3/10, SMB 445 firewall, RDP 3389, new local admin 4720 |
| **Success** | Escalate with MITRE **T1021**; containment plan |
| **Mistakes** | Single failed login labeled lateral movement |

### Data exfil indicator

| | |
|--|--|
| **Goal** | Unusual upload/DNS/bytes out |
| **Actions** | Proxy/firewall bytes; rare domain; off-hours bulk |
| **Success** | Escalate; “contain” narrative without deleting logs |
| **Mistakes** | Cloud backup job not cross-checked (FP) |

### Vulnerability / patch urgency (scanner finding)

| | |
|--|--|
| **Goal** | Risk vs exploit vs asset criticality |
| **Actions** | CVSS + exposure (internet?) + owner |
| **Success** | Ticket to client with due date; not same as incident close |
| **Mistakes** | Treating every CVE as CRITICAL incident |

---

## 6. Customer and scope boundaries

### Must not do without approval

| Action | Approval |
|--------|----------|
| **Isolate host / disable user** | Lead + SOAR approve step |
| **Firewall allow/deny production change** | Client + lead |
| **Delete logs** | Never |
| **Mass password reset** | Client contact for VIP accounts |
| **Notify law enforcement** | Jason / client exec |

**Scope:** Documented in onboarding (`client_onboarding_skill`): audit-only vs SIEM vs both; VPN required yes/no.

**Authorization record:** Ticket `summary`, `next_action`, timeline event; integration page per client (`/analyst/client/<id>/integration`).

### Sample customer update (ticket note / email)

> Subject: Boundry monitoring — authentication alert (NorthPeak)  
>  
> We detected multiple failed sign-in attempts against your environment between 06:48 and 06:52 UTC from a single internet address. We did **not** see a successful sign-in from that address. We recommended blocking that address at the perimeter and resetting passwords for the affected accounts. MFA remains enforced. No further action needed from you unless you see unexpected lockouts. Reply if you want a call.

---

## 7. Jargon glossary (Boundry / shop usage)

| Term | As we use it |
|------|----------------|
| **BT ticket** | Boundry case ID `BT-YYYY-NNNN` |
| **Finding** | Correlated or scanner issue in `system_findings` |
| **Notable** | Same idea as detection / finding (we avoid Splunk-only slang with clients) |
| **Disposition** | `true_positive` \| `false_positive` \| `escalate` |
| **FP** | False positive — benign or expected |
| **TP** | True positive — real issue |
| **IOC** | IP, hash, domain, URL worth enriching |
| **TTP** | MITRE ATT&CK technique (e.g. T1110) |
| **Enrich** | Intel lookup + context before escalate |
| **Contain** | Limit blast radius (isolate, block, disable session) |
| **Triage** | First-pass severity + verdict + next action |
| **SPL** | Search Processing Language (Splunk-style; we use SPL-lite) |
| **Correlation** | Rule fired from many events → one finding |
| **Shift** | Practice queue with SLA minutes (`/career/shift`, `/soc`) |
| **Path A** | Weekly SIEM report (revenue cadence) |
| **Control Room** | Analyst HQ dashboard (green theme) |
| **Prove it** | Pass ≥70% quiz to unlock next training lesson (Career Hub) |
| **Ollama triage** | Local AI 4-bullet note: WHAT / INTENT / ACTIONS / VERDICT |
| **Kill switch** | NordVPN setting; pre-client checklist item |
| **Client tag** | Fictional tenant label on practice alerts |

---

## 8. SLAs and pressure (game meters)

**Target response (training defaults from shift bank):**

| Severity | Typical `sla_minutes` in sim |
|----------|------------------------------|
| CRITICAL | 8–12 |
| HIGH | 15–20 |
| MEDIUM | 25–35 |
| LOW / INFO | 40–45 |

**Leadership metrics (awareness):**

- **MTTD** — rule fired → ticket opened  
- **MTTR** — ticket opened → closed  
- **FP rate** — tuning quality  
- **SLA breach count** — shift score  
- **Customer satisfaction** — report delivered on time (Path A)

**Burning SLA feels like:** Clock red on mission board; CRITICAL still `new` while analyst chases INFO Defender scan.

**Boundry reality:** Pre-revenue; SLAs are **targets in sim**, not contractual yet.

---

## 9. Mission seeds for PenTrace (5 × 15–30 min)

| # | Working title | Player role | Win condition | Primary skills taught |
|---|---------------|-------------|---------------|------------------------|
| 1 | **SLA Race: Password Spray** | L1 on shift (NorthPeak) | Correct TP; block narrative; client note; under 10 min | Spray vs brute; MITRE T1110.003; priority queue |
| 2 | **BT Ticket from Correlation** | L1 | Open BT from finding; SPL confirms; close TP with IOC | SIEM search, correlation, documentation |
| 3 | **VPN Scare vs Change Window** | L1 | FP close citing CHG ticket; no escalation | Change management; vpn_monitor noise |
| 4 | **4720 at 3 AM** | L1 → escalate | `escalated` with handoff; no unauthorized isolate | Persistence; scope boundaries; SOAR approve fantasy beat |
| 5 | **Friday Path A Report** | Analyst (Jason-hat optional) | 7-day pull + executive summary + “no SECRETS” mail | Monitoring ≠ incident; retainer value; different win state |

### Additional mission candidates (§ request: 3–5 flagged)

- **Phish wire request** — `/career/email` pattern; BEC disposition  
- **Firewall 445 storm** — perimeter held; TP but low drama  
- **Weekly + incident same shift** — multitasking meter  

---

## 10. Off-limits

Must **never** appear in game build:

- Real Boundry client names, domains, emails, or API keys  
- Real client business names (use **GreenLeaf**-style fiction only)  
- Jason’s home IP, NordVPN account details, `.terminal_token`, `SECRET_KEY`, live `app.db` exports  
- Licensed vendor splash screens passed off as real integrations (Splunk, CrowdStrike, Microsoft) — use **“SIEM”, “EDR console sim”, “Sentinel-style”** per `ENTERPRISE_SECOPS_UX.md` honesty banner  
- Messer / private curriculum text in game  
- Instructions to run destructive commands on real endpoints  

**OK:** TEST-NET IPs (`203.0.113.x`, `198.51.100.x`), fictional tenants Contoso/NorthPeak/Harbor, BT ticket format, MITRE public IDs.

---

## Boundry-specific deltas (summary for PenTrace)

| Generic MSSP | Boundry today |
|--------------|---------------|
| 24/7 NOC | Training shifts + on-demand monitoring build |
| ServiceNow | `soc_cases` + markdown progress files |
| Cloud SIEM SaaS | Local Flask + SQLite/Postgres |
| CrowdStrike live | Career EDR sim |
| Mandiant retainer | Jason + playbooks |
| AI in SOC | Ollama on-machine triage only |

---

## Return path

Paste this file into PenTrace Project chat or link from `gamified-training-methodology.md` when available. Cross-map: §2–4 → mail / contract board / timer; §5–7 → terminal + Index; §8 → SLA meters; §9 → mission YAML M7+.
