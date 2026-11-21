# Upgrade Open WebUI then run local LLM audit (after plugin/package changes).
$ErrorActionPreference = 'Stop'

pip install -U open-webui
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'Restart Open WebUI from launch-boundry-ai.bat or manually on 127.0.0.1:8080 when convenient.'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Dev\MSSP\tools\audit_local_llm.ps1'
exit $LASTEXITCODE
