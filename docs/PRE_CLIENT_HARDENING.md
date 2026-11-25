# Pre-client hardening checklist (M1–M9)

Track go-live readiness. Details in PRD §6.1.  
**Held for Roy:** service tiers and 5-minute demo script.

| ID | Item | How | Status |
|----|------|-----|--------|
| M1 | `SECRET_KEY` env + `FLASK_DEBUG=false` | Set system/user env `SECRET_KEY` (token_urlsafe 64). Launch bat already sets `FLASK_DEBUG=false`. Confirm with `echo %SECRET_KEY%` / process env. | Config (Jason) |
| M2 | Client isolation (`client_id` tags) | `mssp_tenants` + ingest→SIEM; analyst **Client scope** on `/siem` and `?tenant=` on `/api/siem/events` + SOC queue API. | Code shipped; set scope per client when triaging |
| M3 | Demo cannot see real client data | Demo logs in as client role; reports scoped by `owner_id`. Ops/Career/SIEM/SOC routes hard-blocked for client/demo. | Code shipped |
| M4 | Alert path | Resend (`RESEND_API_KEY`) logs to `alert_log`; Gmail via `alert_monitor.py` for on-prem. | Partial until OPS-04 configured |
| M5 | NordVPN kill switch ON | NordVPN app → Settings → Kill Switch → enable. Verify via `/api/vpn/status` (`kill_switch: true`). | Host setting (Jason) |
| M6 | Daily `app.db` backup | Run/register `tools/backup_app_db.ps1` (see below). | Script shipped |
| M7 | Privacy one-pager | [PRIVACY_DATA_HANDLING.md](PRIVACY_DATA_HANDLING.md) | Shipped |
| M8 | Mini IR path | [IR_MINI_PATH.md](IR_MINI_PATH.md) | Shipped |
| M9 | Local LLM hardening (Ollama + Open WebUI) | Loopback bind, firewall 11434/8080/5000, secrets in `%USERPROFILE%\.boundry\secrets.env`, WebUI auth + tool lockdown. Weekly audit: [tools/register_llm_audit_scheduler.ps1](../tools/register_llm_audit_scheduler.ps1); details [LOCAL_LLM_HARDENING.md](LOCAL_LLM_HARDENING.md). | Script + doc shipped; Jason: run [tools/run_harden_ports_elevated.bat](../tools/run_harden_ports_elevated.bat) once (UAC); register weekly audit; configure WebUI auth in UI |

## Register M6 Task Scheduler (once)

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\backup_app_db.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:15AM
Register-ScheduledTask -TaskName "BoundryAI-AppDbBackup" -Action $action -Trigger $trigger -Force
```

Prefer destination `D:\BoundryBackups` when that drive exists.

Weekly verify (optional): `powershell -File tools\backup_app_db.ps1 -Verify`

## Health watchdog (GAP-010)

```powershell
powershell -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\install_boundry_service.ps1 -AppUrl http://127.0.0.1:5000
```

Probes `GET /health` every 5 minutes. Set `-RestartCommand` to your Flask start script if you want auto-restart.

## Live mode + cron (before internet-facing clients)

| Env | Purpose |
|-----|---------|
| `SECRET_KEY` | M1 — dev shows yellow banner on Control Room until set |
| `CRON_SECRET` | Required when `BOUNDRY_MODE=live`; failed cron auth → SIEM event |
| `BOUNDRY_MODE=live` | 404 on `/training`, `/career`, `/cissp`, `/demo`, `/simulate-attack` |
| `RESEND_API_KEY` + `FROM_EMAIL` | Client alert emails + `alert_log` rows |

## M1 generate secret

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
# Then: System Properties → Environment Variables → SECRET_KEY = <value>
# Restart Flask / launch-boundry-ai.bat
```
