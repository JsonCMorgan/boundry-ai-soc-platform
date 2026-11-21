# SOC / MSSP L1 Skills Roadmap (Security+ hire path)

**Audience:** Jason, GTA Canada, CompTIA Security+ (SY0-701) + Boundry Career Hub  
**Target roles:** SOC Tier-1 / Associate SOC Analyst / Junior Cyber Defender / MSSP L1  
**Sources (2025–2026):** Wiz Tier-1 guide, Vectra SOC tiers, nflo SOC tiers, Apex/UltraViolet JD patterns, Canadian MSSP posts (MNP, Ontinue, EY managed services)  
**Last updated:** 2026-10-03

This file is the **standing backlog** for Boundry Training Hub enhancements.  
When proposing new Career / training features, map them to a gap ID below (G1–G20).

---

## Role snapshot

With Security+, employers expect you to be the **front line**: watch alerts, triage true vs false positive, follow playbooks, document tickets, escalate cleanly, and talk the case. They do **not** expect you to own detection engineering, malware RE, or architecture on day one.

---

## A. Covered now (skill / responsibility → Boundry)

| # | Skill / responsibility | How Boundry helps today |
|---|------------------------|-------------------------|
| C1 | Security fundamentals (CIA, controls, IAM, crypto, IR phases) | `/career/secplus` micro-curriculum; glossary hovers; CISSP hub (deeper) |
| C2 | Alert monitoring & queue triage | `/career/shift` (Quick/Standard); Control Room; live `/siem` |
| C3 | True positive vs false positive judgment | Shift alerts; Interview Gym `powershell_fp`, `escalate_vs_close`; Training scenarios |
| C4 | Follow playbooks / SOP-style steps | `/soar` approve-gated actions; `/playbooks`; Interview skeleton (validate→decide) |
| C5 | Escalate vs close with a clear reason | Interview Gym; Shift dispositions; Training results |
| C6 | Ticket / case documentation | Shift case console (SLA + summary/next); `/career/portfolio` PDF; `/reports` |
| C7 | SIEM search fluency (Splunk-style) | `/career/spl` + `/siem/query` (SPL-lite) |
| C8 | KQL / Sentinel mental model | `/career/kql` (per-section quizzes); `/career/sentinel` blades |
| C9 | Phishing / BEC triage talk-track | `/career/email` header lab; Interview Gym + variants; Sec+ Domain 2 |
| C10 | Identity alerts (spray, impossible travel, MFA) | Interview Gym; SIEM auth events; Sec+ ops lessons; `/career/logs` M365 drill; `/career/entra` CA |
| C11 | EDR mental model (process tree, isolate, FP) | `/career/edr` console sim; Interview Gym EDR scenarios; findings / scan |
| C18 | Log source literacy (4625/4688, FW, proxy, M365) | `/career/logs` flashcards + name-the-evidence drills |
| C19 | Enrichment / IOC lookup before escalate | `/career/intel` local reputation stub + ticket note |
| C20 | Networking for analysts (ports / DNS / HTTP / east-west) | `/career/net` Learn spine + flashcards + signal drills |
| C21 | Vulnerability triage (CVSS vs exploit vs asset) | `/career/vuln` priority + disposition queue |
| C12 | Lateral movement / RDP suspicion | Interview Gym `lateral_rdp`; Sec+ / training scenarios |
| C13 | MITRE ATT&CK tagging basics | Shift MITRE field; `/training` + MITRE detail; portfolio |
| C14 | Interview walkthroughs (HM format) | `/career/interview` Guided→Coached→Live + New angle variants |
| C15 | Soft glossary / jargon fluency | Platform-wide hover + `/glossary` |
| C16 | Local AI as coach (not cloud client data) | Boundry Tutor on Sec+/SPL/Interview; Ollama-first |
| C17 | Prove-it practice rhythm | Career Hub Today’s drill + prove-it gates |

---

## B. Gaps (future enhancement backlog)

Priority bands: **P0** = hire-critical soon · **P1** = strong differentiator · **P2** = nice later

| ID | Gap (skill / responsibility) | Why it matters on JDs | Suggested Boundry direction | Priority | Status |
|----|------------------------------|------------------------|-----------------------------|----------|--------|
| G1 | Real email triage (headers / `.eml` / auth results) | Phishing is daily L1 work | Header lab: paste `.eml` or sample → SPF/DKIM/DMARC checklist → disposition | P0 | ✅ `/career/email` |
| G2 | Commercial ticket fields (ServiceNow-style) | MSSPs live in ticket SLAs | Expand ticket hygiene into a “case console” with SLA timer, client tag, queue state | P0 | ✅ Shift case console (SLA + summary/next) |
| G3 | Multi-client / multi-tenant queue | MSSP reality ≠ single queue | Shift mode: 2–3 fake clients, priority + SLA race | P0 | ✅ Contoso / NorthPeak / Harbor tags |
| G4 | Vendor EDR console muscle (Defender / Falcon UI patterns) | JDs name tools | “EDR console sim”: process tree, isolate, timeline (no real vendor needed) | P0 | ✅ `/career/edr` |
| G5 | Sentinel workspace practice beyond KQL syntax | Canadian MSSPs lean Microsoft | Map KQL lessons to fake Sentinel blades (alerts, entities, hunting) | P1 | ✅ `/career/sentinel` |
| G6 | Enrichment / threat intel lookup workflow | L1 enriches before escalate | Local IOC bench: IP/hash/domain → reputation stub + ticket note | P1 | ✅ `/career/intel` (local stub, no cloud) |
| G7 | Vulnerability scan triage (not just “run scan”) | Many L1 JDs mention vuln support | Vuln queue: CVSS vs exploitability vs asset criticality → ticket | P1 | ✅ `/career/vuln` |
| G8 | Log source literacy (Windows 4625/4688, firewall, proxy, M365) | “Read the log” interviews | Log flashcards + “name the evidence” drills tied to Shift | P1 | ✅ `/career/logs` |
| G9 | Networking for analysts (ports, DNS, HTTP, east-west) | Always on screening lists | Analyst networking course (SOC-focused, not CCNA): Show me → Help me → Prove it + drills | P1 | ✅ `/career/net` (14 lessons) |
| G10 | Linux basics for SOC | Appears on many L1 lists | Mini Linux-for-logs track (auth.log, sudo, cron) | P2 | ⬜ |
| G11 | Cloud identity / Entra Conditional Access reading | M365-heavy clients | Identity storyboard: CA policy outcome → alert explanation | P1 | ✅ `/career/entra` |
| G12 | Email security gateway concepts (Proofpoint-class) | Named on US MSSP JDs | Gateway triage panel: quarantine, URL rewrite, impersonation | P2 | ⬜ |
| G13 | SOAR beyond approve/reject (enrich → contain chain) | Automation is on 2026 lists | Multi-step playbook runner with human gates | P1 | ✅ `/career/soar` |
| G14 | Shift / follow-the-sun / handover notes | 24/7 SOC culture | End-of-shift handoff generator + grading rubric | P1 | ✅ `/soc` handoff rubric |
| G15 | Stakeholder comms (user callbacks, VIP, client updates) | Soft skill that fails interviews | Comms Gym: draft user email / client update / escalate note | P1 | ✅ `/career/comms` |
| G16 | Metrics literacy (MTTD/MTTR, FP rate) — awareness only | Managers / owners ask; L1 should speak it | One lesson + dashboard widget explaining the metrics | P1 | ✅ `/career/metrics` |
| G17 | Detection tuning awareness (why alert is noisy) | Bridge to L2 / AI-SOC oversight | “Tune or tolerate” drills after FP cases | P1 | ✅ `/career/tune` |
| G18 | Scripting lite (PowerShell/Python for enrichment) | Increasingly listed | Optional Automation Lite track (safe local scripts) | P1 | ✅ `/career/automation` |
| G19 | Clearance / Reliability eligibility literacy (Canada) | Some federal/MSSP posts | Checklist page: what employer sponsors; what you prepare | P2 | ⬜ |
| G20 | Recorded Live interview clips + self-rubric | Proof for applications | One-click “record walkthrough notes” export beside Live score | P1 | ⬜ |
| G21 | AI / agent verdict oversight | 2026 SOCs automate triage; humans validate | Autopilot Oversight Gym: stub agent verdict (sometimes wrong) → agree/override + evidence | P1 | ✅ `/career/oversight` |
| G22 | Automation policy (auto vs approve vs never) | MSSP owners design human gates per tenant | Per Practice client: enrich auto / approve contain / never auto | P1 | ✅ `/career/automation-policy` |

---

## C. How to use this file

1. **Do not** start random Hub features. Pick a **G#**.
2. Prefer **P0** until Security+ is passed and applications are active.
3. Every new module should state: which G# it closes, Show→Help→Watch→Prove path, and how it feeds portfolio/interview proof.
4. Keep Ollama-first; no silent cloud for client-like data.

---

## D. Suggested next build order (when Jason greenlights)

1. ~~G1 Email header lab~~ ✅
2. ~~G3 Multi-client shift queue~~ ✅
3. ~~G2 Case console / SLA fields~~ ✅
4. ~~G4 EDR console sim~~ ✅
5. ~~G8 Log source literacy~~ ✅ `/career/logs`
6. ~~G6 Local IOC enrichment bench~~ ✅ `/career/intel` (Option A: offline stub, no VT/Shodan)
7. ~~G9 Networking for analysts~~ ✅ `/career/net` (Option A: flashcards + signal drills)
8. ~~G7 Vulnerability queue~~ ✅ `/career/vuln` (Option A: CVSS vs exploit vs asset triage)
9. ~~G5 Sentinel workspace blades~~ ✅ `/career/sentinel` (Incidents / Entities / Hunting)
10. ~~G11 Entra Conditional Access~~ ✅ `/career/entra` (CA storyboard → disposition)
    (Futureproof P1: G13 SOAR chain, G21 oversight, G17 tune, G16 metrics, G22 automation policy, G18 lite; G14/G15 shipped)

Sec+ study and Interview Gym variants stay parallel. They feed C1 and C14, not the gap list.

Job Skills eras: **foundation** (classic L1) → **tomorrow** (SOAR/AI oversight) → **owner** (metrics + automation policy). Sec+ study time still first.
