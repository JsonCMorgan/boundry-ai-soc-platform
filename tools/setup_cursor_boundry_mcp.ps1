# Register Boundry local MCP (security + Ollama routing) in Cursor user mcp.json
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File C:\Dev\MSSP\tools\setup_cursor_boundry_mcp.ps1

$ErrorActionPreference = 'Stop'

$serverPy = 'C:\Dev\boundry-mcp-server\server.py'
if (-not (Test-Path -LiteralPath $serverPy)) {
    Write-Error "Missing $serverPy"
}

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) {
    Write-Error 'python not on PATH'
}

$mcpJson = Join-Path $env:USERPROFILE '.cursor\mcp.json'
$vt = if ($env:VIRUSTOTAL_API_KEY) { $env:VIRUSTOTAL_API_KEY } else { '' }
$sh = if ($env:SHODAN_API_KEY) { $env:SHODAN_API_KEY } else { '' }

$py = @"
import json
import os
from pathlib import Path

mcp_json = Path(os.environ['USERPROFILE']) / '.cursor' / 'mcp.json'
mcp_json.parent.mkdir(parents=True, exist_ok=True)
config = {'mcpServers': {}}
if mcp_json.is_file():
    try:
        config = json.loads(mcp_json.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        config = {'mcpServers': {}}
if 'mcpServers' not in config or not isinstance(config['mcpServers'], dict):
    config['mcpServers'] = {}

config['mcpServers']['boundry-ai'] = {
    'command': r'$($python -replace '\\', '\\\\')',
    'args': [r'$($serverPy -replace '\\', '\\\\')'],
    'env': {
        'BOUNDRY_MSSP_ROOT': r'C:\\Dev\\MSSP',
        'OLLAMA_BASE_URL': 'http://127.0.0.1:11434',
        'VIRUSTOTAL_API_KEY': os.environ.get('BOUNDRY_SETUP_VT', ''),
        'SHODAN_API_KEY': os.environ.get('BOUNDRY_SETUP_SHODAN', ''),
    },
}
mcp_json.write_text(json.dumps(config, indent=2), encoding='utf-8')
print(mcp_json)
"@

$env:BOUNDRY_SETUP_VT = $vt
$env:BOUNDRY_SETUP_SHODAN = $sh
& $python -c $py
Remove-Item Env:BOUNDRY_SETUP_VT -ErrorAction SilentlyContinue
Remove-Item Env:BOUNDRY_SETUP_SHODAN -ErrorAction SilentlyContinue

Write-Host 'Restart Cursor and enable MCP server: boundry-ai'
Write-Host 'Docs: C:\Dev\MSSP\docs\LLM_ROUTING_WORKFLOW.md'