# Boundry Option A port harden (Administrator required)
# - Disable LanmanServer (stops SMB 445 / NetBIOS 139 listening)
# - Ensure inbound Block rules: 135, 139, 137, 138, 445, 8080, 11434, 5000
# - Restart Open WebUI bound to 127.0.0.1 only
#
# Non-admin shells fail with "Access is denied" on Set-NetFirewallRule.
# Use: tools\run_harden_ports_elevated.bat  (UAC prompt, then runs this script)
param(
    [switch]$StayOpen
)

$ErrorActionPreference = 'Stop'

$isAdmin = (
    [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ''
    Write-Host 'ERROR: This script must run as Administrator (firewall + LanmanServer).'
    Write-Host ''
    Write-Host 'From repo root, double-click or run:'
    Write-Host '  C:\Dev\MSSP\tools\run_harden_ports_elevated.bat'
    Write-Host ''
    Write-Host 'Or: Start PowerShell as Administrator, then:'
    Write-Host '  Set-ExecutionPolicy Bypass -Scope Process -Force'
    Write-Host '  & C:\Dev\MSSP\tools\_harden_ports_option_a.ps1 -StayOpen'
    Write-Host ''
    exit 5
}

$log = @()

function Ensure-BlockRule {
    param([string]$Name, [string]$Protocol, [string]$Port)
    $existing = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Block `
            -Protocol $Protocol -LocalPort $Port -Profile Any -Enabled True | Out-Null
        $script:log += "FW_CREATED $Name"
    } else {
        Set-NetFirewallRule -DisplayName $Name -Enabled True -Action Block | Out-Null
        $script:log += "FW_OK $Name"
    }
}

Ensure-BlockRule 'BoundryAI Block RPC Port 135' 'TCP' '135'
Ensure-BlockRule 'BoundryAI Block SMB Port 445' 'TCP' '445'
Ensure-BlockRule 'BoundryAI Block NetBIOS Session 139' 'TCP' '139'
Ensure-BlockRule 'BoundryAI Block NetBIOS Name 137' 'UDP' '137'
Ensure-BlockRule 'BoundryAI Block NetBIOS Datagram 138' 'UDP' '138'
Ensure-BlockRule 'BoundryAI Block Open WebUI 8080' 'TCP' '8080'
Ensure-BlockRule 'BoundryAI Block Ollama 11434' 'TCP' '11434'
Ensure-BlockRule 'BoundryAI Block Flask 5000' 'TCP' '5000'

# Disable Server service (file/printer sharing from this PC)
Stop-Service LanmanServer -Force
Set-Service LanmanServer -StartupType Disabled
$log += 'LanmanServer STOPPED+DISABLED'

# Restart Open WebUI on localhost only
$listen = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique
foreach ($procId in $listen) {
    if ($procId) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        $log += "KILLED_WEBUI_PID $procId"
    }
}
Start-Sleep -Seconds 2
$exe = 'C:\Users\ricka\AppData\Local\Programs\Python\Python311\Scripts\open-webui.exe'
Start-Process -FilePath $exe -ArgumentList 'serve','--host','127.0.0.1','--port','8080' -WindowStyle Minimized
$log += 'WEBUI_STARTED 127.0.0.1:8080'
Start-Sleep -Seconds 6

$log += '---LISTEN---'
$log += (netstat -ano | Select-String -Pattern 'LISTENING' | Select-String -Pattern ':135 |:139 |:445 |:8080 |:5000 |:11434 ').Line
$log += '---SERVICES---'
$svc = Get-Service LanmanServer | Select-Object Name, Status, StartType
$log += "$($svc.Name) Status=$($svc.Status) StartType=$($svc.StartType)"
$log += '---FIREWALL---'
Get-NetFirewallRule -DisplayName 'BoundryAI*' | ForEach-Object {
    $log += "$($_.DisplayName) Enabled=$($_.Enabled) Action=$($_.Action)"
}

$outPath = 'C:\Dev\MSSP\tools\_harden_ports_option_a_result.txt'
$log | Set-Content -Path $outPath -Encoding UTF8
Write-Host ($log -join "`n")
Write-Host "`nRESULT_FILE=$outPath"

if ($StayOpen) {
    Write-Host ''
    Read-Host 'Press Enter to close this Administrator window'
}
