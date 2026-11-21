# Ensure inbound TCP 8765 is allowed on Private (phone pitch quiz on Wi-Fi).
# Run elevated: Right-click PowerShell -> Run as administrator.
$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Re-run as Administrator." -ForegroundColor Red
    exit 1
}

$name = "BoundryAI Allow Cafe Quiz 8765"
$rule = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
if ($rule) {
    Set-NetFirewallRule -DisplayName $name -Enabled True -Action Allow | Out-Null
    Write-Host "OK: firewall rule '$name' is enabled." -ForegroundColor Green
} else {
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 8765 -Profile Private,Domain -Enabled True | Out-Null
    Write-Host "Created firewall rule '$name' (TCP 8765, Private)." -ForegroundColor Green
}

Write-Host ""
Write-Host "Port 5000 is still blocked from the LAN by design (port hardening)."
Write-Host "Use tools\launch_pitch_phone.ps1 — it binds Flask on 8765 for phones."
Write-Host ""