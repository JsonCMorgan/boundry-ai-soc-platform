# Remove secret keys from C:\Dev\MSSP\.env after migrate_secrets_to_boundry_home.ps1.
# Leaves a pointer comment; non-secret flags (ENABLE_MESSER_LAYER, etc.) stay.
$ErrorActionPreference = 'Stop'
$envPath = 'C:\Dev\MSSP\.env'
$secretKeys = @(
    'SECRET_KEY', 'GMAIL_APP_PASSWORD', 'ANTHROPIC_API_KEY', 'RESEND_API_KEY',
    'DEMO_USERNAME', 'DEMO_PASSWORD', 'ANALYST_USERNAME', 'ANALYST_PASSWORD',
    'CRON_SECRET', 'CRON_PASS', 'TERMINAL_TOKEN', 'RESET_TOKEN', 'ABUSEIPDB_API_KEY',
    'DATABASE_URL', 'SPLUNK_HEC_TOKEN'
)
if (-not (Test-Path $envPath)) {
    Write-Host 'No .env to trim.'
    exit 0
}
$out = New-Object System.Collections.Generic.List[string]
[void]$out.Add('# Secrets live in %USERPROFILE%\.boundry\secrets.env (see docs/LOCAL_LLM_HARDENING.md)')
Get-Content $envPath -Encoding UTF8 | ForEach-Object {
    $line = $_.TrimEnd()
    if ($line -match '^\s*#' -or $line -match '^\s*$') { return }
    if ($line -match '^([^=]+)=') {
        $k = $matches[1].Trim()
        if ($secretKeys -contains $k) { return }
    }
    [void]$out.Add($line)
}
$out | Set-Content -Path $envPath -Encoding UTF8
Write-Host 'Trimmed secret keys from C:\Dev\MSSP\.env'
