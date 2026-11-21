# Run after changing models: ollama pull <name> then local LLM audit.
# Usage: .\ollama_pull_audit.ps1 llama3.1:8b
param(
    [Parameter(Mandatory = $true, ValueFromRemainingArguments = $true)]
    [string[]]$ModelArgs
)

$ErrorActionPreference = 'Stop'
if (-not $ModelArgs -or $ModelArgs.Count -eq 0) {
    Write-Error 'Usage: ollama_pull_audit.ps1 <model>  (same args as ollama pull)'
}

& ollama pull @ModelArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Dev\MSSP\tools\audit_local_llm.ps1'
exit $LASTEXITCODE
