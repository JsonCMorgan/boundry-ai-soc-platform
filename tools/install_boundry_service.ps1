# Boundry.AI — Windows health watchdog (GAP-010)
# Registers a Task Scheduler job that hits GET /health every 5 minutes.
# Optionally restarts Flask if health fails (set $RestartCommand when using NSSM/manual script).

param(
  [string]$AppUrl = "http://127.0.0.1:5000",
  [string]$TaskName = "BoundryAI-HealthWatch",
  [string]$RestartCommand = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProbeScript = Join-Path $ScriptDir "_health_probe.ps1"

@"
param([string]`$AppUrl = '$AppUrl', [string]`$RestartCommand = '$RestartCommand')
try {
  `$r = Invoke-RestMethod -Uri "`$AppUrl/health" -TimeoutSec 8 -Method Get
  if (-not `$r.ok) { throw "health not ok: `$(`$r | ConvertTo-Json -Compress)" }
  exit 0
} catch {
  Write-Warning "Boundry health check failed: `$_"
  if (`$RestartCommand) {
    Write-Host "Running restart: `$RestartCommand"
    Invoke-Expression `$RestartCommand
  }
  exit 1
}
"@ | Set-Content -Encoding UTF8 $ProbeScript

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ProbeScript`""

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
  -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
  -Description "Boundry /health probe every 5 min" -Force | Out-Null

Write-Host "Registered $TaskName -> $AppUrl/health (every 5 min)"
Write-Host "To restart on failure, re-run with -RestartCommand 'your start command'"