# Copy boundry-showcase into Jason's Netlify digital_card folder as /hq/
$ErrorActionPreference = "Stop"
$Mssp = $PSScriptRoot + "\.."
$CardRoot = "C:\Users\ricka\Projects\jason-job-agent\profile\digital_card"
$Src = Join-Path $Mssp "public\boundry-showcase"
$Dst = Join-Path $CardRoot "hq"

if (-not (Test-Path $CardRoot)) {
    Write-Host "ERROR: Digital card folder not found: $CardRoot" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $Src "index.html"))) {
    Write-Host "ERROR: Missing $Src\index.html" -ForegroundColor Red
    exit 1
}

if (Test-Path $Dst) { Remove-Item $Dst -Recurse -Force }
New-Item -ItemType Directory -Path $Dst | Out-Null
Copy-Item -Path (Join-Path $Src "*") -Destination $Dst -Recurse -Force

$CfgPath = Join-Path $CardRoot "config.json"
if (-not (Test-Path $CfgPath)) {
    Write-Host "ERROR: Missing config.json (linkedin_url): $CfgPath" -ForegroundColor Red
    exit 1
}
$Cfg = Get-Content $CfgPath -Raw | ConvertFrom-Json
$LinkedIn = ($Cfg.linkedin_url | ForEach-Object { "$_".Trim() })
if (-not $LinkedIn) {
    Write-Host "ERROR: linkedin_url empty in config.json" -ForegroundColor Red
    exit 1
}

function Set-HqLinkedInUrl {
    param([string]$HqIndex)
    if (-not (Test-Path $HqIndex)) { return }
    $html = Get-Content $HqIndex -Raw
    $html = $html.Replace('__JASON_LINKEDIN_URL__', $LinkedIn)
    $html = $html.Replace('https://www.linkedin.com/in/jasonmorgan', $LinkedIn)
    $pat = '(?<=href=")https://www\.linkedin\.com/in/[^"]*(?="[^>]*>LinkedIn)'
    $html = [regex]::Replace($html, $pat, $LinkedIn)
    Set-Content -Path $HqIndex -Value $html -NoNewline -Encoding utf8
}

Set-HqLinkedInUrl (Join-Path $Dst "index.html")

$DocsCard = Join-Path $env:USERPROFILE "Documents\Jason Morgan Job Applications\digital_card"
if (Test-Path $DocsCard) {
    $DocsHq = Join-Path $DocsCard "hq"
    if (Test-Path $DocsHq) { Remove-Item $DocsHq -Recurse -Force }
    Copy-Item -Path $Dst -Destination $DocsCard -Recurse -Force
    Set-HqLinkedInUrl (Join-Path $DocsHq "index.html")
    Write-Host "Also copied hq to: $DocsHq" -ForegroundColor Green
    Write-Host "LinkedIn (tour): $LinkedIn" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Copied showcase to: $Dst" -ForegroundColor Green
Write-Host "Public URL: https://fanciful-fox-c753db.netlify.app/hq/" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next:"
Write-Host "  1) python C:\Users\ricka\Projects\jason-job-agent\scripts\build_digital_business_card.py"
Write-Host "  2) Re-upload Documents\Jason Morgan Job Applications\digital_card to Netlify (fanciful-fox-c753db)"
Write-Host ""