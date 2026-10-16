# SIEM Phase A — false positive reduction

**Audience:** Jason (home Boundry stack)  
**Last updated:** 2026-10-16  

## What shipped

1. **Firewall severity matrix** — Internet scanners hitting non-risky ports ingest as `firewall_block_background` (INFO) and do **not** count toward the Firewall Port Scan correlation rule.
2. **Quick FP templates** — One click on SIEM correlation findings: suppress + resolve (where applicable).
3. **Ingest tune module** — [`siem_ingest_tunes.py`](../siem_ingest_tunes.py) centralizes vendor noise (NordVPN NEP* 7045 today).

Restart Flask after collector changes (`launch-boundry-ai.bat` or restart `app.py`).

## Analyst workflow

### SIEM live stream

- **INFO** rows include internet background firewall drops. Use **Clear INFO** or dismiss if the stream feels busy.
- **HIGH** firewall blocks and auth events still correlate and can open findings.

### Open correlation findings

| Button | When to use |
|--------|-------------|
| **FP: Internet scan** | Firewall Port Scan from a public scanner IP you do not care about |
| **FP: Vendor service** | New Service Installed that is expected vendor noise (NEP/NordVPN is tuned at ingest) |
| **FP: Doc test IP** | Finding mentions 203.0.113.x, 198.51.100.x, or 192.0.2.x (lab/doc IPs) |

Quick FP **suppresses the IP** (scan + doc templates) and **closes the finding** as false positive.

Manual **False Positive** still works but does not suppress future events from that IP.

### What still escalates

- Audit log cleared (CRITICAL)
- Brute force from non-doc IPs with evidence of success
- LAN-sourced firewall blocks on risky ports (445, 3389, etc.)
- Unknown service installs (not matched by ingest tune)

## SPL examples

```
event_type=firewall_block | stats count by src_ip
event_type=firewall_block_background | head 20
event_type=service_installed_benign | table description created_at
```

## Adding an ingest tune

Edit `tune_windows_event()` in [`siem_ingest_tunes.py`](../siem_ingest_tunes.py). Return `TuneResult` with `correlate=False` for noise you still want in the audit trail.

## Phase B (not yet)

- Rule threshold presets in UI  
- Auto-ticket gate on `/soc` Real lane  
