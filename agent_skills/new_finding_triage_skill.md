# New Finding Triage Skill — Boundry.AI

Triage a HIGH or CRITICAL finding from Control Room or SIEM with AI-assisted analysis, dedup check, and escalation decision.

---

## Purpose

Respond quickly and consistently when a HIGH/CRITICAL finding appears — produce an analyst triage note, update status, escalate if warranted.

## Prerequisites

- Analyst session on Boundry.AI (`@analyst_required` routes)
- Ollama running (required for AI triage — returns 503 if unavailable)
- Finding ID from Control Room, SIEM dashboard, or `GET /scan/findings`

---

## Inputs

| Input | Required | Example |
|-------|----------|---------|
| `finding_id` | Yes | `42` (database `system_findings.id`) |
| `source` | Optional | `control_room` \| `siem` \| `scanner` |

---

## Trigger conditions

Run this skill when:

- Control Room shows unresolved finding with severity **HIGH** or **CRITICAL**
- SIEM correlation creates `system_findings` row with `scan_type='siem'`
- `GET /api/siem/stats` shows elevated `critical_hour` or `open_findings`
- Alert email from `alert_monitor.py` (if configured)

---

## Steps

### 0. CONCEPT — Progress file

Create `agent_tasks/new_finding_triage_<finding_id>_progress.md`.

---

### 1. Read the finding

**API:**
```
GET /scan/findings
```

Returns JSON array of open findings. Locate `id == finding_id`.

Fields to capture:
- `id`, `finding_id`, `title`, `severity`, `category`, `description`
- `recommendation`, `scan_type`, `created_at`, `cissp_domain`

**UI alternatives:**
- Control Room — findings panel
- SIEM dashboard (`GET /siem`) — correlated SIEM findings section
- Terminal: `bai findings`

Abort with BLOCKED if finding not found or already resolved.

---

### 2. Check duplicates

Search for similar open findings:

```
GET /scan/findings
```

Filter same `finding_id` code OR similar `title` / same `category` within 24h.

Also search related SIEM events:
```
GET /api/siem/search?q=<keyword_from_title>&severity=CRITICAL,HIGH&limit=50
```

Document in progress file:
- Duplicate? yes/no
- If duplicate, link related finding IDs and recommend merge/resolve workflow

---

### 3. Map MITRE ATT&CK

1. Extract technique hints from `category`, `title`, `description`.
2. Reference playbook: `GET /mitre/<technique_id>` (e.g. `/mitre/T1110` for brute force).
3. Training cross-ref: `mitre_reference.py` / Control Room MITRE links.

Record MITRE ID + name in progress file.

---

### 4. Run AI retriage (SIEM findings)

For findings with `scan_type='siem'`, use the hardened retriage endpoint (~line 5803 `app.py`):

```
POST /api/siem/findings/<finding_id>/triage
```

- Requires analyst session cookie
- Calls `_generate_report_with_ai(prompt)` with sanitized finding fields
- Updates `system_findings.ai_triage` column
- Returns: `{ "ok": true, "triage": "<4-bullet analyst note>" }`

**503 response:** `"AI backend unavailable — is Ollama running?"` — start Ollama, retry.

**Prompt output format** (from `api_siem_retriage`):
- WHAT HAPPENED
- INTENT (MITRE / kill chain)
- IMMEDIATE ACTIONS (2 numbered steps)
- VERDICT (real attack / false positive / needs investigation)

For **scanner findings** (`scan_type != 'siem'`):

Use remediation context:
```
GET /scan/findings/<finding_id>/remediation-plan
```

Then draft triage note manually or via Cursor using same 4-bullet format and `_generate_report_with_ai` prompt pattern (do not expose unsanitized user input to AI).

---

### 5. Draft analyst note

Combine into deliverable note in progress file:

```markdown
## Triage Note — Finding #{finding_id}
**Severity:** {severity}
**MITRE:** {technique_id} {technique_name}
**Verdict:** {verdict}
**AI triage:** {paste from ai_triage or step 4}

### Analyst assessment
{1-2 sentences Jason adds/edits}

### Actions taken
- [ ] {action 1}
- [ ] {action 2}

### Escalation
{none | client notify | emergency — reason}
```

Optional — save to reports workflow:
```
POST /reports/<report_id>/notes     — if tied to incident report
POST /reports/<report_id>/triage    — status: new|reviewing|escalated|closed
```

---

### 6. Escalate if needed

Escalate when:
- CRITICAL + active attack indicators (VPN down, brute force success, credential stuffing succeeded)
- Client data exposure likely
- Repeat finding after prior resolution

Actions:
1. Set report/finding status: `POST /reports/<id>/triage` with `status=escalated`
2. Notify Jason via Slack MCP (when configured) — see `docs/MCP_SETUP.md`
3. Email client if retainer includes incident response (manual until GMAIL_APP_PASSWORD set)
4. Resolve when fixed: `POST /scan/findings/<finding_id>/resolve` (+25 XP via `award_xp`)

Terminal resolve: `bai resolve <id>`

---

### 7. REVISION_COMPLETE — Verification

- [ ] Finding read and recorded accurately
- [ ] Duplicate check documented
- [ ] MITRE mapping recorded
- [ ] AI triage run OR manual 4-bullet note complete
- [ ] Escalation decision explicit (yes/no + reason)
- [ ] Progress file has full triage note
- [ ] No secrets/PII over-shared in note

---

### 8. TASK_COMPLETE

Handoff:
- Triage note path (progress file section)
- Whether client notification needed
- Link to SIEM events (`/siem?` or search query used)
- Follow-up time if `needs investigation`

---

## Artifacts

| Artifact | Path |
|----------|------|
| Progress file | `agent_tasks/new_finding_triage_<finding_id>_progress.md` |
| Triage note | Section inside progress file; `ai_triage` column in DB for SIEM findings |

---

## Boundry.AI routes referenced

| Route | Method | Use |
|-------|--------|-----|
| `/scan/findings` | GET | List open findings |
| `/scan/findings/<id>/remediation-plan` | GET | Scanner remediation details |
| `/scan/findings/<id>/resolve` | POST | Mark resolved |
| `/api/scan/findings` | GET | Terminal/bai findings list |
| `/api/siem/findings/<id>/triage` | POST | **AI retriage** (`api_siem_retriage`) |
| `/api/siem/search` | GET | Related events |
| `/api/siem/stats` | GET | Open findings count |
| `/mitre/<technique_id>` | GET | MITRE playbook |
| `/reports/<id>/triage` | POST | Report status update |
| `/reports/<id>/notes` | POST | Analyst notes on report |
| `/control-room` | GET | Finding source UI |
| `/siem` | GET | SIEM finding context |

**AI function:** `_generate_report_with_ai()` via `api_siem_retriage` (~line 5803–5854 `app.py`).

**DB tables:** `system_findings` (`ai_triage`, `scan_type`, `resolved`), `siem_events`, `analyst_notes`.

---

## Revenue hook

Fast triage protects retainer clients and justifies monitoring value. CRITICAL escalations may trigger incident-response billing (document in Stripe as one-time invoice via `create_invoice` when MCP connected).

---

## Verification

Step 7 checklist complete. For SIEM findings, confirm `ai_triage` populated:

```sql
SELECT ai_triage FROM system_findings WHERE id = ?;
```

Status `TASK_COMPLETE`.
