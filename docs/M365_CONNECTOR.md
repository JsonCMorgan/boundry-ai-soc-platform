# M365 / Entra log ingest — Phase 1 (manual)

**Status:** Phase 1 shipped (`POST /api/m365/ingest`). Phase 2 OAuth poller not built.

## Phase 1 (today)

1. Export unified audit logs from Entra / Microsoft 365 (JSON array or `{"value": [...]}`).
2. POST to Boundry:

```http
POST /api/m365/ingest
X-API-Key: <client api key>
Content-Type: application/json
```

3. Events land in `siem_events` with `client_id` = tenant slug; correlation rules for `m365_signin_failed` and `vendor_app_consent` apply.

Parser: `m365_ingest.py`.

## Phase 2 (planned)

- Entra app registration (audit log read).
- Refresh token stored encrypted in `app_settings` per tenant.
- Scheduled poller (daemon thread or Task Scheduler hitting local cron).

## Privacy

Ops data stays on-machine. Do not forward raw M365 exports to cloud LLMs.