# Run until quiz_answer_verify_report.json has complete=true (~910 MCQs, local Ollama).
# Use a normal PowerShell window (not Cursor background tasks) so the job is not killed.
param(
    [switch]$Fresh
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$report = "content\private\messer\curriculum\quiz_answer_verify_report.json"
$stdout = "content\private\messer\curriculum\quiz_verify_stdout.log"
$stderr = "content\private\messer\curriculum\quiz_verify_stderr.log"

if ($Fresh -and (Test-Path $report)) {
    Remove-Item $report -Force
}

Get-CimInstance Win32_Process -Filter "name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*messer_verify_quiz_answers.py*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Remove-Item "content\private\messer\curriculum\.quiz_verify.lock" -Force -ErrorAction SilentlyContinue

$env:PYTHONUNBUFFERED = "1"

function Test-AuditComplete {
    if (-not (Test-Path $report)) { return $false }
    $j = Get-Content $report -Raw | ConvertFrom-Json
    return ($j.complete -eq $true)
}

function Show-Status {
    python tools/messer_quiz_audit_status.py
}

Write-Host "Boundry Messer quiz audit - Ollama must be running (llama3.1:8b)." -ForegroundColor Cyan
Show-Status

while (-not (Test-AuditComplete)) {
    Write-Host ''
    Write-Host 'Starting verify pass with resume flag...' -ForegroundColor Yellow
    $p = Start-Process -FilePath "python" `
        -ArgumentList @("tools/messer_verify_quiz_answers.py", "--resume") `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -NoNewWindow -PassThru -Wait
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 2) {
        Write-Host "Verify exited with code $($p.ExitCode). Retrying in 10s..." -ForegroundColor Red
        Start-Sleep -Seconds 10
    }
    Show-Status
    if (Test-AuditComplete) { break }
    Start-Sleep -Seconds 5
}

Write-Host ''
Write-Host 'Audit complete. Review failures, then run:' -ForegroundColor Green
Write-Host '  python tools/messer_verify_quiz_answers.py --apply'
Write-Host '  python tools/messer_quiz_audit_status.py'
