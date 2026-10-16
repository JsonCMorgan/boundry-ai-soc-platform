# Pre-client hardening checklist (M1–M8)

Track go-live readiness. Details in PRD §6.1.  
**Held for Roy:** service tiers and 5-minute demo script.

| ID | Item | How | Status |
|----|------|-----|--------|
| M1 | `SECRET_KEY` env + `FLASK_DEBUG=false` | Set system/user env `SECRET_KEY` (token_urlsafe 64). Launch bat already sets `FLASK_DEBUG=false`. Confirm with `echo %SECRET_KEY%` / process env. | Config (Jason) |
| M2 | Client isolation (`client_id` tags) | `mssp_tenants` table + `system_findings.client_id` / `siem_events.client_id` columns; filter helpers for future multi-tenant queries. Default tenant `boundry_self`. | Code shipped; use tags before real client data |
| M3 | Demo cannot see real client data | Demo logs in as client role; reports scoped by `owner_id`. Ops/Career/SIEM/SOC routes hard-blocked for client/demo. | Code shipped |
| M4 | Alert path | Prefer Gmail app password + AlertMonitor. Local alternate documented in [IR_MINI_PATH.md](IR_MINI_PATH.md). | Partial until Gmail configured |
| M5 | NordVPN kill switch ON | NordVPN app → Settings → Kill Switch → enable. Verify via `/api/vpn/status` (`kill_switch: true`). | Host setting (Jason) |
| M6 | Daily `app.db` backup | Run/register `tools/backup_app_db.ps1` (see below). | Script shipped |
| M7 | Privacy one-pager | [PRIVACY_DATA_HANDLING.md](PRIVACY_DATA_HANDLING.md) | Shipped |
| M8 | Mini IR path | [IR_MINI_PATH.md](IR_MINI_PATH.md) | Shipped |

## Register M6 Task Scheduler (once)

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\backup_app_db.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:15AM
Register-ScheduledTask -TaskName "BoundryAI-AppDbBackup" -Action $action -Trigger $trigger -Force
```

Prefer destination `D:\BoundryBackups` when that drive exists.

## M1 generate secret

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
# Then: System Properties → Environment Variables → SECRET_KEY = <value>
# Restart Flask / launch-boundry-ai.bat
```
