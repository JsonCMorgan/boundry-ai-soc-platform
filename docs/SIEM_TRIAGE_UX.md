# SIEM triage click-through UX

Analyst workflow on `/siem`: stats filter the stream, event rows open a triage drawer, tickets hand off to SOC Floor.

## Stats (clickable)

| Stat | Action |
|------|--------|
| **Events Today** | Search mode, calendar today (`from` / `to` = local date). Matches DB count (`date(created_at) = date('now')` on SQLite). |
| **Critical (1h)** | Search mode, last hour, severity CRITICAL only. |
| **High (1h)** | Search mode, last hour, severity HIGH only. |
| **Open Findings** | Scroll to Correlation Findings panel (Quick FP on finding rows). |

Deep links:

- `/siem?range=today`
- `/siem?range=1h&severity=CRITICAL,HIGH`
- `/siem?event=<id>` — opens triage drawer for that event.

## Event row → triage drawer

Click any row (not the ✕ dismiss button). Actions:

- **Open Boundry Ticket** / **Resume ticket** — `POST /api/soc/cases/open` with `source=siem`.
- **Open ticket + start work** — open + transition to `working`.
- **Continue on SOC Floor** — `/soc?case=<id>` or `/soc?open=siem:<event_id>`.
- **Investigate in SPL** — `/siem/query?q=...` (prefilled hint).
- **Suppress this IP** — opens suppression modal when `src_ip` is set.
- **False positive** — dismiss event.

Related events (24h, same IP or type) appear at the bottom of the drawer.

The drawer **Observables** strip lists entities (IPs from columns and alert text, user, host, type). Copy the primary IOC or jump to SOC Floor for local enrich lookup.

## APIs

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/siem/events/<id>` | Event detail + `spl_hint`, `existing_case`, `correlated_finding` |
| GET | `/api/siem/events/<id>/related` | Up to 10 related events |

## SOC Floor handoff

- `/soc?open=siem:<event_id>` — creates or resumes ticket, then URL becomes `/soc?case=<id>`.
- MEDIUM/LOW events are not on the default SOC queue; ticket from the SIEM drawer instead.

## Observables on tickets (enterprise-style)

When a ticket is opened from a SIEM event, **Ticket workspace** shows an **Observables** panel (IPs, user, host, event type) with **Copy** / **Enrich**, plus links to SIEM and SPL. The enrich box pre-fills the primary IP. **Evidence / IOC** gets a starter line when empty. Enrichment results show a verdict card (local stub) and append to Evidence / IOC.

## Manual smoke

1. Hard refresh `/siem`.
2. Click **Events Today** — search results should match the stat.
3. Click a log row — drawer loads; **Open Boundry Ticket** shows ticket number.
4. **Continue on SOC Floor** — ticket console populated.
5. `/soc?open=siem:<id>` — same case without hunting the queue.

## Tests

```bash
pytest tests/test_siem_event_detail.py -q
```
