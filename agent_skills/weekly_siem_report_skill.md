# Weekly SIEM Report Skill — Boundry.AI

**Path A priority — revenue.** Produce a client-ready weekly SIEM monitoring report and verify billing.

---

## Purpose

Generate a 7-day SIEM executive summary + technical appendix for a Boundry.AI monitoring client, suitable for email delivery and monthly retainer justification.

## Prerequisites

- Flask app running at `http://localhost:5000` (or production URL)
- Logged in as **analyst** (`session role=analyst`) — required for all SIEM API routes
- Ollama running (`http://localhost:11434`) — primary AI backend per `.cursorrules`
- Client identifier: **username** in `users` table (role `client`) or agreed tenant label
- NordVPN monitor active if client requires VPN (`vpn_monitor.py`)
- Optional: Splunk HEC configured (`SPLUNK_HEC_TOKEN`)

**Known limitation:** Client data isolation is not yet implemented (single `siem_events` table). For multi-client, filter by `host`, ingest source, or client-specific API key events until `client_id` tagging ships. Document which filter you used in the progress file.

---

## Inputs

| Input | Required | Example |
|-------|----------|---------|
| `client_name` | Yes | `GreenLeaf` |
| `client_username` | Yes (for owner lookup) | `greenleaf_admin` |
| `report_date` | Yes | `2026-05-27` |
| `host_filter` | Optional | `greenleaf-app` |

---

## Steps

### 0. CONCEPT — Initialize progress file

Create `agent_tasks/weekly_siem_report_<client_name>_<report_date>_progress.md` using the template in `__how_to_take_notes.md`.

Set **What**: Weekly SIEM report for `<client_name>`, covering last 7 days.

---

### 1. Resolve client account

1. Open Control Room: `GET /control-room` — lists all users (`id`, `username`, `role`).
2. Confirm client exists: `users.username = <client_username>` AND `role = 'client'`.
3. Note `client_id` (user `id`) for integration link: `GET /analyst/client/<client_id>/integration`.
4. Record `owner_id` — used if cross-referencing `reports` table for same client.

**DB fallback (read-only):**
```sql
SELECT id, username, role, api_key FROM users WHERE username = ? AND role = 'client';
```

---

### 2. Pull last 7 days SIEM events

**Preferred — authenticated API** (session cookie from analyst login):

#### 2a. Full event search (7-day window)

```
GET /api/siem/search?from=<7_days_ago>&to=<report_date>&limit=500
```

Query params (from `api_siem_search` in `app.py`):
- `from` — start date `YYYY-MM-DD`
- `to` — end date `YYYY-MM-DD` (inclusive through 23:59:59)
- `severity` — optional comma list: `CRITICAL,HIGH`
- `source` — optional comma list: `windows_event,firewall,vpn_monitor,...`
- `q` — optional full-text search
- `limit` — max 500

Returns: `{ "events": [...], "total": N, "query": "..." }`

#### 2b. Severity timeline (charts data)

```
GET /api/siem/timeline?window=7d
```

Returns Chart.js-ready buckets by severity for the last 7 days.

#### 2c. Live dashboard stats (context)

```
GET /api/siem/stats
```

Returns: `total_today`, `critical_hour`, `high_hour`, `open_findings`.

#### 2d. SPL aggregations (top event types, severity counts)

Use SPL-lite via:

```
GET /api/siem/spl?q=<url_encoded_spl>
```

Example queries (via `/siem/query` UI or API):

| Goal | SPL query |
|------|-----------|
| Count by severity | `earliest=-7d | stats count by severity` |
| Top event types | `earliest=-7d severity=CRITICAL OR severity=HIGH | stats count by event_type | sort -count | head 10` |
| By source | `earliest=-7d | stats count by source` |
| VPN events | `earliest=-7d source=vpn_monitor | sort -timestamp | head 20` |

SPL engine: `spl_engine.parse_spl()` — see `.cursorrules` for supported commands.

#### 2e. DB fallback (if API unavailable)

```sql
SELECT severity, COUNT(*) AS cnt
FROM siem_events
WHERE dismissed = 0
  AND created_at >= datetime('now', '-7 days')
GROUP BY severity;

SELECT event_type, COUNT(*) AS cnt
FROM siem_events
WHERE dismissed = 0
  AND created_at >= datetime('now', '-7 days')
GROUP BY event_type
ORDER BY cnt DESC
LIMIT 10;
```

Log event counts in the progress file per-edit table.

---

### 3. Correlation summary & open findings

1. **Open SIEM findings:**
   ```
   GET /scan/findings
   ```
   Filter JSON for `scan_type == 'siem'` and `severity IN ('CRITICAL','HIGH')`.

2. **Correlation rules:** Review active rules on `GET /siem` page (loaded server-side from `siem_rules`).

3. Summarize in progress file:
   - Total events (7d)
   - Count by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO)
   - Top 5 `event_type` values
   - Open SIEM findings count
   - Notable correlation firings (rule name + count if visible in finding titles)

---

### 4. Infrastructure health checks

#### VPN status
```
GET /api/vpn/status
```
Returns NordVPN connection state from `vpn_monitor.get_vpn_status()`.
Flag any CRITICAL `vpn_monitor` SIEM events in the 7-day window.

#### Splunk forwarder health
```
GET /api/splunk/status
```
Returns HEC forwarder state from `splunk_forwarder.get_status()`.
Note if `SPLUNK_HEC_TOKEN` unset (forwarder is no-op — document as "not configured").

Optional hotload (session only, not persisted):
```
POST /api/splunk/token
Content-Type: application/json
{"token": "<hec_token>"}
```

---

### 5. Generate executive summary + technical appendix (AI)

Use the existing AI pipeline pattern from `_generate_report_with_ai()` in `app.py` (Ollama first, Anthropic fallback). **Do not rewrite app code** — construct a prompt and either:

**Option A — Cursor agent generates directly** (preferred for weekly SIEM):
Build a prompt with the aggregated data from steps 2–4 and ask Ollama via local inference or have Cursor draft the report sections.

**Option B — Incident agent for security_events** (different data source):
```
POST /run-agent
```
Runs `_run_agent_core()` against `security_events` (web app attack sim / ingest events), **not** raw `siem_events`. Use only if the client also has `/api/ingest` events tied to their `owner_id`. Weekly SIEM reports should primarily use step 2 data.

**Prompt structure** (adapt from incident report template ~line 3291 in `app.py`):

```markdown
You are a senior SOC analyst at Boundry.AI writing a WEEKLY SIEM MONITORING REPORT.

Client: {client_name}
Period: {start_date} to {end_date}

Data summary:
{json_summary_from_steps_2_4}

Write these sections in clean markdown:

## Executive Summary
3-4 sentences for the business owner. Plain English. Overall risk posture this week.

## Week at a Glance
Table: Severity | Count | Trend note (up/down vs prior week if known)

## Top Activity
Bullet list of top event types and what they mean for this client.

## Correlation & Findings
Open SIEM findings, correlation rule hits, recommended analyst actions.

## Infrastructure Status
VPN: {vpn_status}. Splunk forwarder: {splunk_status}.

## Technical Appendix
- Event count by source
- Sample CRITICAL/HIGH events (max 5, redact PII)
- SPL queries used for this report

## Recommended Actions
Immediate (24h) / This week / Hardening
```

Pass through `_generate_report_with_ai` logic conceptually: local Ollama `llama3.1:8b` at `http://localhost:11434/v1/chat/completions`.

---

### 6. Write final report artifact

Save to:

```
docs/reports/weekly_siem_<client_name>_<report_date>.md
```

Also store reference in progress file **Where** section.

Optional PDF: if Jason needs PDF, use existing `GET /reports/<id>/pdf` flow after saving to DB — or `pdf_generator.py` manually. Weekly reports may stay markdown until a dedicated export route exists.

---

### 7. Stripe — verify or create recurring subscription (manual until MCP connected)

**When Stripe MCP is connected** (see `docs/MCP_SETUP.md`), run these tools in order:

| Step | Stripe MCP tool | Purpose |
|------|-----------------|---------|
| 7a | `list_customers` | Find client by email or metadata |
| 7b | `create_customer` | If missing — name + email + metadata `{boundry_client: "<client_name>"}` |
| 7c | `list_products` / `list_prices` | Find "Boundry.AI SIEM Monitoring" product (create if absent) |
| 7d | `list_subscriptions` | Verify active monthly subscription for customer |
| 7e | `create_invoice` + `create_invoice_item` + `finalize_invoice` | First invoice or catch-up billing |

Official tool names from [Stripe MCP docs](https://docs.stripe.com/mcp): `create_customer`, `list_customers`, `create_product`, `create_price`, `list_subscriptions`, `update_subscription`, `create_invoice`, `create_invoice_item`, `finalize_invoice`, `list_invoices`.

**Jason manual prompt (until OAuth done):**
> "Using Stripe MCP, list customers matching `<client_email>`. If no active subscription for SIEM Monitoring monthly price, create customer and draft invoice for $XXX/month. Record customer ID and subscription ID in the progress file."

**Without MCP:** Jason performs the same steps in Stripe Dashboard. Record IDs in progress file.

---

### 8. REVISION_COMPLETE — Verification checklist (~10 minutes)

Jason (or agent) confirms:

- [ ] Progress file exists and reflects all steps
- [ ] 7-day event total matches `/api/siem/search?from=...&to=...` total (or DB count)
- [ ] Severity breakdown matches SPL `stats count by severity`
- [ ] VPN status checked via `/api/vpn/status`
- [ ] Splunk status checked via `/api/splunk/status`
- [ ] Final markdown saved to `docs/reports/weekly_siem_<client>_<date>.md`
- [ ] Executive summary readable by non-technical client contact
- [ ] No raw secrets, API keys, or `.terminal_token` in report
- [ ] Stripe customer/subscription noted (or BLOCKED with reason)
- [ ] Handoff note: email draft or delivery method specified

---

### 9. TASK_COMPLETE

Set progress status `TASK_COMPLETE`. Add **Handoff**:

- Report path to attach/send
- Stripe subscription status
- Next report due date (+7 days)
- Any escalations from open CRITICAL findings

---

## Artifacts

| Artifact | Path |
|----------|------|
| Progress file | `agent_tasks/weekly_siem_report_<client>_<date>_progress.md` |
| Final report | `docs/reports/weekly_siem_<client>_<date>.md` |
| Stripe refs | In progress file (customer ID, subscription ID) |

---

## Boundry.AI routes referenced

| Route | Method | Use |
|-------|--------|-----|
| `/control-room` | GET | Client list |
| `/analyst/client/<id>/integration` | GET | Client API key + ingest URL |
| `/api/siem/search` | GET | 7-day event pull |
| `/api/siem/timeline?window=7d` | GET | Severity timeline |
| `/api/siem/stats` | GET | Dashboard counts |
| `/api/siem/spl?q=...` | GET | SPL aggregations |
| `/api/siem/events` | GET | Live feed (optional) |
| `/scan/findings` | GET | Open system findings |
| `/api/vpn/status` | GET | NordVPN health |
| `/api/splunk/status` | GET | HEC forwarder health |
| `/api/splunk/token` | POST | Hotload HEC token |
| `/siem` | GET | SIEM dashboard UI |
| `/siem/query` | GET | SPL query UI |
| `/run-agent` | POST | AI incident report (security_events — secondary) |
| `/reports` | GET | Saved reports list |
| `/reports/<id>/pdf` | GET | PDF export |

**AI function:** `_generate_report_with_ai(prompt)` in `app.py` (~line 2952) — Ollama primary, Anthropic fallback.

**DB tables:** `siem_events`, `system_findings` (scan_type=`siem`), `siem_rules`, `splunk_forwarder_state`, `users`, `reports`.

---

## Revenue hook

This skill is the **monthly retainer deliverable**. After TASK_COMPLETE:

1. Email report to client contact (plain text intro + markdown/PDF attachment)
2. Confirm Stripe subscription active (`list_subscriptions`)
3. Log next run in calendar: same day next week

---

## Verification

See step 8 checklist. Minimum bar: report file exists, counts match API, Stripe status recorded.
