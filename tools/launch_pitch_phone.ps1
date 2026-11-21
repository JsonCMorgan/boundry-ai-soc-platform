# Start Boundry Flask on port 8765 so phones can reach /pitch (LAN firewall allows 8765, blocks 5000).
Set-Location $PSScriptRoot\..
$env:FLASK_BIND_HOST = "0.0.0.0"
$env:FLASK_PORT = "8765"

function Get-PhoneLanIps {
    $vpnHints = @("NordLynx", "WireGuard", "Tailscale", "TAP", "Wintun", "OpenVPN", "NordVPN")
    $addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.PrefixOrigin -ne "WellKnown"
        }
    $rows = foreach ($a in $addrs) {
        $alias = (Get-NetIPInterface -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceAlias
        $isVpn = $false
        if ($alias) {
            foreach ($h in $vpnHints) {
                if ($alias -like "*$h*") { $isVpn = $true; break }
            }
            if ($a.IPAddress -like "10.100.*" -or $a.IPAddress -like "10.5.*") { $isVpn = $true }
        }
        [pscustomobject]@{ IP = $a.IPAddress; Vpn = $isVpn; Alias = $alias }
    }
    $wifi = @($rows | Where-Object { -not $_.Vpn })
    $vpn = @($rows | Where-Object { $_.Vpn })
    ,(@($wifi) + @($vpn) | ForEach-Object { $_.IP } | Select-Object -Unique)
}

$ips = Get-PhoneLanIps
if (-not $ips -or $ips.Count -eq 0) { $ips = @("10.0.0.2") }
$phoneIp = $ips[0]

Write-Host ""
Write-Host '  Pitch quiz LAN mode: port 8765 (not 5000; firewall blocks LAN on 5000).' -ForegroundColor Cyan
Write-Host '  Keep this window open while you use your phone.' -ForegroundColor Cyan
Write-Host ''
Write-Host ('  [1] PC check:  http://{0}:8765/pitch' -f $phoneIp) -ForegroundColor Green
Write-Host '  [2] Phone:     same URL in Safari (same WiFi, not cellular).' -ForegroundColor Green
Write-Host '  [3] iPhone:    Share menu, Add to Home Screen, open once online.' -ForegroundColor Green
Write-Host ""
Write-Host "  If PC works but phone fails: Ethernet must be 'Private' (Settings -> Network)."
Write-Host "  One-time admin: .\tools\ensure_pitch_phone_firewall.ps1"
Write-Host ""
Write-Host "  Do NOT use localhost or 127.0.0.1 on the phone."
Write-Host ""

$block = Get-NetFirewallRule -DisplayName "BoundryAI Block Flask 5000" -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq "True" -and $_.Action -eq "Block" }
if ($block) {
    Write-Host '  (BoundryAI Block Flask 5000 is on; that is why we use 8765 here.)' -ForegroundColor DarkYellow
    Write-Host ""
}

python app.py