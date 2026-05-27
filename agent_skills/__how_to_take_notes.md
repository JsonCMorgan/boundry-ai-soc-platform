# How to Take Notes — Boundry.AI Progress Files

Every skill run maintains a **progress file** in `agent_tasks/`. This file is the source of truth — not the chat transcript.

## Required sections

Use this template at the top of every progress file:

```markdown
# Progress: <skill name> — <client or subject>
**Status:** IN_PROGRESS | REVISION_COMPLETE | TASK_COMPLETE
**Started:** YYYY-MM-DD HH:MM
**Last updated:** YYYY-MM-DD HH:MM
**Operator:** Jason Morgan

## What
One sentence — what this run is delivering.

## Where
Paths to artifacts (progress file, final report, Stripe customer ID, etc.).

## Why
Business context — retainer client, first report, escalation, etc.

## What remains
Bulleted list of incomplete steps. Empty when TASK_COMPLETE.
```

## Status vocabulary

| Status | Meaning |
|--------|---------|
| `IN_PROGRESS` | Active work; at least one step incomplete |
| `REVISION_COMPLETE` | All steps done; running verification checklist |
| `TASK_COMPLETE` | Verified; ready for Jason to deliver or bill |
| `BLOCKED` | Waiting on Jason (MCP OAuth, client reply, missing env var) |

## Per-edit log

Append a row after **every** EDIT phase:

| Timestamp | Step | Action | Result |
|-----------|------|--------|--------|
| 2026-05-27 09:15 | 2 | Pulled 7d events via `/api/siem/search` | 847 events |
| 2026-05-27 09:22 | 5 | Generated exec summary via Ollama prompt | Draft saved |

## What to capture

- **API responses** — counts, error messages, HTTP status (not full PII dumps)
- **Decision points** — "escalated because 3 CRITICAL VPN drops"
- **Stripe IDs** — customer ID, subscription ID, invoice ID (when MCP connected)
- **Blockers** — "Stripe MCP not OAuth'd — Jason must connect manually"

## What NOT to capture

- Full passwords, API keys, or `.terminal_token` contents
- Entire SIEM event payloads (summarize instead)
- Speculation marked as fact

## Closing a run

When status becomes `TASK_COMPLETE`:

1. Set **What remains** to `(none)`
2. Add a **Handoff** section: what Jason sends to the client, what to invoice, follow-up date
3. Do not delete the progress file — archive locally if needed
