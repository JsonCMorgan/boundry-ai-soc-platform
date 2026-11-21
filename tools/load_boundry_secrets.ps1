# Build a one-shot batch file from %USERPROFILE%\.boundry\secrets.env for launch-boundry-ai.bat.
# Does not print secret values.
$secretsPath = Join-Path $env:USERPROFILE '.boundry\secrets.env'
$outBat = Join-Path $env:USERPROFILE '.boundry\_runtime_env.bat'

if (-not (Test-Path $secretsPath)) {
    if (Test-Path $outBat) { Remove-Item $outBat -Force -ErrorAction SilentlyContinue }
    exit 0
}

$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add('@echo off')
Get-Content -Path $secretsPath -Encoding UTF8 | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith('#')) { return }
    $eq = $line.IndexOf('=')
    if ($eq -lt 1) { return }
    $key = $line.Substring(0, $eq).Trim()
    $val = $line.Substring($eq + 1).Trim().Trim('"')
    if ($key -match '[^\w]') { return }
    $escaped = $val -replace '%', '%%'
    [void]$lines.Add("set `"$key=$escaped`"")
}

$dir = Split-Path $outBat -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$lines | Set-Content -Path $outBat -Encoding ASCII
