# Mission Control queue

Splunk ES-style unified triage at `/soc/mission`.

## Queue types

| Type | Source | Open |
|------|--------|------|
| `finding` | `system_findings` (unresolved) | Finding detail / Open SOAR |
| `case` | `soc_cases` (not closed) | `/soc?case=<id>` |
| `soar` | `soar_incidents` (open) | `/soar?id=<id>` |

## Saved views

Query param `view`: `all`, `new`, `in_progress`, `unassigned`.

## API

- `GET /api/soc/mission/queue?view=all`
- `POST /api/soc/mission/bulk-action` — `start_work` on case, `open_soar` on finding
