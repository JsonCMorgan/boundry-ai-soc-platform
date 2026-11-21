# Read-only local LLM / Boundry stack audit (Kai video checklist).
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\audit_local_llm.ps1
#        ... -FailOnWarn   (exit 1 if WARN lines — for Task Scheduler)
#        ... -Quiet        (minimal console output)
param(
    [switch]$FailOnWarn,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$log = @("Boundry local LLM audit - $ts", '')

function Add-Line { param([string]$Line) $script:log += $Line }

Add-Line '=== Ollama ==='
try {
    Add-Line (ollama --version 2>&1 | Out-String).Trim()
} catch {
    Add-Line 'ollama: not in PATH'
}
$hostVar = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'User')
if (-not $hostVar) { $hostVar = [Environment]::GetEnvironmentVariable('OLLAMA_HOST', 'Machine') }
if (-not $hostVar) { $hostVar = $env:OLLAMA_HOST }
if ($hostVar) {
    Add-Line "OLLAMA_HOST=$hostVar"
    if ($hostVar -match '0\.0\.0\.0|::|\*:') {
        Add-Line 'WARN: OLLAMA_HOST exposes all interfaces - set 127.0.0.1 or unset'
    }
} else {
    Add-Line 'OLLAMA_HOST=(unset - default loopback OK)'
}

Add-Line ''
Add-Line '=== ollama list ==='
try {
    Add-Line (ollama list 2>&1 | Out-String).Trim()
} catch {
    Add-Line 'ollama list failed'
}

Add-Line ''
Add-Line '=== Open WebUI (pip) ==='
$pip = pip show open-webui 2>&1 | Select-String '^Version:'
if ($pip) { Add-Line ($pip.Line) } else { Add-Line 'open-webui: not installed via pip' }

Add-Line ''
Add-Line '=== Listen ports (11434 / 8080 / 5000) ==='
$ports = @(11434, 8080, 5000)
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) {
        Add-Line "Port $port : not listening"
        continue
    }
    foreach ($c in $conns) {
        $addr = $c.LocalAddress
        $flag = if ($addr -eq '127.0.0.1' -or $addr -eq '::1') { 'OK' } else { 'WARN non-loopback' }
        Add-Line "Port $port : $addr $($flag)"
    }
}

Add-Line ''
Add-Line '=== Firewall (BoundryAI*) ==='
Get-NetFirewallRule -DisplayName 'BoundryAI*' -ErrorAction SilentlyContinue | ForEach-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $portsStr = ($portFilter.LocalPort -join ',')
    Add-Line "$($_.DisplayName) Enabled=$($_.Enabled) Action=$($_.Action) Port=$portsStr"
}

Add-Line ''
Add-Line '=== Secrets path ==='
$secrets = Join-Path $env:USERPROFILE '.boundry\secrets.env'
Add-Line "External secrets: $(if (Test-Path $secrets) { 'present' } else { 'MISSING - run tools/migrate_secrets_to_boundry_home.ps1' })"
$msspEnv = 'C:\Dev\MSSP\.env'
if (Test-Path $msspEnv) {
    Add-Line 'WARN: C:\Dev\MSSP\.env still exists - prefer ~/.boundry/secrets.env (run trim_mssp_dotenv.ps1)'
}

Add-Line ''
Add-Line '=== Model allowlist (tools) ==='
Add-Line 'See docs/LOCAL_LLM_HARDENING.md and tools/ollama_tool_allowlist.txt'

$outDir = 'C:\Dev\MSSP\tools'
$outFile = Join-Path $outDir ('_audit_local_llm_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
$log | Set-Content -Path $outFile -Encoding UTF8

# Keep last 14 audit logs
Get-ChildItem $outDir -Filter '_audit_local_llm_*.txt' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip 14 |
    Remove-Item -Force -ErrorAction SilentlyContinue

$hasWarn = ($log | Where-Object { $_ -match '^WARN:' -or $_ -match ' WARN ' }).Count -gt 0
if (-not $Quiet) {
    Write-Host ($log -join "`n")
    Write-Host "`nWrote $outFile"
    if ($hasWarn) { Write-Host 'NOTE: one or more WARN lines — review log.' }
}

if ($FailOnWarn -and $hasWarn) { exit 1 }
exit 0
