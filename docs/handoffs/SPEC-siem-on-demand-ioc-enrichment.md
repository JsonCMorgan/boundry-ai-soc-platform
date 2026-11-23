# SPEC: SIEM on-demand IOC enrichment (Boundry MSSP)

**Status:** Shipped v1 (2026-11-23). See `docs/SIEM_IOC_ENRICHMENT.md`.

**Maps to:** G6 (intel enrich habit), Live SIEM UX (Stage 4b), `intel_lab.lookup_ioc` stub.

**Portfolio repo `ioc-extractor` stays separate** — no package dependency.

---

## Goal

Analyst triggers **Enrich indicators** from the SIEM UI on a **selected event** (not auto-enrich on every ingest). Return local stub context for IPs, domains, hashes found on that event.

## Non-negotiables

1. Default path: `intel_lab.lookup_ioc()` / `REPUTATION` only. **No silent cloud** (VT, AbuseIPDB, Shodan).
2. Optional future flag for MCP/cloud with explicit UI warning (out of scope for v1).
3. `db_*` + `{PH}`; `@analyst_required` on routes; SIEM cyan UI; vanilla `fetch`.
4. Scoped pytest; no `git push` without Jason confirm.

## Build

### API

`POST /api/siem/enrich`

- Body: `{ "ioc": "203.0.113.88" }` and/or `{ "event_id": 123 }`
- `event_id`: load `siem_events`, extract indicators from `src_ip`, `dst_ip`, `description`, `raw` JSON.
- Response: `{ "source": "local_stub", "indicators_found": [...], "enrichment": [...], "defanged": {...} }`

### UI

- `templates/siem.html` (or event detail): per-row or selection **Enrich indicators** panel.
- Copy-friendly defanged values; label **practice stub**.

### Docs

- Short section in `docs/ENTERPRISE_SECOPS_UX.md` or `docs/SIEM_IOC_ENRICHMENT.md`.

## Acceptance

- [x] Logged-in analyst enriches a real `siem_events` row.
- [x] Stub hit/miss for known IPs (e.g. `203.0.113.88`, `8.8.8.8`).
- [x] No outbound HTTP on default path.
- [x] `tests/test_siem_event_detail.py` covers API.

## Commit message (when shipped)

`feat(siem): on-demand local IOC enrichment from SIEM events`