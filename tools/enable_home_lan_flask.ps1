# Boundry — Home LAN study (office PC)
# Run in an elevated PowerShell window (Right-click → Run as administrator).
# Sets Ethernet/Wi-Fi to Private (if possible), allows TCP 5000 on Private only,
# and prints the bookmark URL for the laptop.

$ErrorActionPreference = "Stop"
$Port = 5000
$RuleName = "Boundry Flask LAN (Private)"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Re-run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "=== Network profiles ===" -ForegroundColor Cyan
Get-NetConnectionProfile | Format-Table Name, InterfaceAlias, NetworkCategory -AutoSize

# Prefer physical LAN (Ethernet / Wi-Fi), skip NordVPN tunnels
$profiles = Get-NetConnectionProfile | Where-Object {
    $_.InterfaceAlias -notmatch "Nord|OpenVPN|TAP|Wintun|Loopback"
}
foreach ($p in $profiles) {
    if ($p.NetworkCategory -ne "Private") {
        Write-Host "Setting '$($p.InterfaceAlias)' ($($p.Name)) → Private ..." -ForegroundColor Yellow
        try {
            Set-NetConnectionProfile -InterfaceIndex $p.InterfaceIndex -NetworkCategory Private
        } catch {
            Write-Host "  Could not change profile: $_" -ForegroundColor Red
            Write-Host "  Change manually: Settings → Network → your connection → Private." -ForegroundColor Yellow
        }
    } else {
        Write-Host "'$($p.InterfaceAlias)' already Private." -ForegroundColor Green
    }
}

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Firewall rule already exists: $RuleName" -ForegroundColor Green
} else {
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound -Protocol TCP -LocalPort $Port `
        -Action Allow -Profile Private | Out-Null
    Write-Host "Created firewall rule: $RuleName (TCP $Port, Private only)" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== LAN IPs (bookmark these) ===" -ForegroundColor Cyan
$ips = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and
    $_.PrefixOrigin -ne "WellKnown" -and
    $_.InterfaceAlias -notmatch "Nord|OpenVPN|TAP|Wintun"
}
$ips | Format-Table IPAddress, InterfaceAlias -AutoSize

foreach ($ip in $ips) {
    Write-Host "Laptop bookmark: http://$($ip.IPAddress):$Port/career/secplus" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Start Boundry with LAN bind:" -ForegroundColor Cyan
Write-Host '  $env:FLASK_BIND_HOST = "0.0.0.0"'
Write-Host '  $env:ENABLE_MESSER_LAYER = "1"'
Write-Host "  python app.py"
Write-Host ""
Write-Host "Done. Keep the office PC awake while studying from the laptop." -ForegroundColor Green
