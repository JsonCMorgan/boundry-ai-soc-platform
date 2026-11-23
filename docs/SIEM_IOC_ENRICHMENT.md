# SIEM on-demand IOC enrichment (Stage 6b)

## What you see

On **SIEM → event drawer**, click **Enrich indicators (local stub)**. Boundry:

1. Pulls IPs (and related IOCs) from the event columns, description, and observables.
2. Looks each up in the **offline** `soc_ioc_stub` table (same data as SOC Floor enrich).
3. Shows a **plain-language summary**, defanged values for copy/paste, and verdict per indicator.

Banner on the panel: **Practice stub only · no cloud lookup**.

## API

`POST /api/siem/enrich` (analyst / dashboard session)

```json
{ "event_id": 123 }
```

or

```json
{ "ioc": "203.0.113.88" }
```

Response includes `plain_summary`, `indicators_found`, `enrichment`, `defanged`, `source: "local_stub"`.

## Privacy

Default path performs **no outbound HTTP**. Live VirusTotal / AbuseIPDB would be a future **opt-in** control only.

## Code

- `siem_ioc_enrich.py` — extract + defang + summary
- `soc_ioc_stub.py` — reputation table
- `app.py` — `api_siem_enrich`
- `templates/siem.html` — drawer UI