# Register weekly Boundry local LLM audit (Task Scheduler).
# Run once from any shell (creates task in current user context).
$ErrorActionPreference = 'Stop'

$taskName = 'BoundryAI-LocalLlmAudit'
$scriptPath = 'C:\Dev\MSSP\tools\audit_local_llm.ps1'
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Quiet -FailOnWarn"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
# Sunday 10:00 local time (adjust if you prefer)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 10:00AM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Description 'Boundry: audit Ollama/WebUI bind, firewall, models (see docs/LOCAL_LLM_HARDENING.md)' `
    -Force | Out-Null

Write-Host "Registered scheduled task: $taskName (Sundays 10:00 AM)"
Write-Host "Logs: C:\Dev\MSSP\tools\_audit_local_llm_*.txt"
Write-Host "Remove: Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false"
