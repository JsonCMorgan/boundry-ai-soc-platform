# Boundry.AI — daily app.db backup (M6)
# Copies C:\Dev\MSSP\app.db to a dated file on a second drive (or fallback folder).
# Register with Task Scheduler (see docs/PRE_CLIENT_HARDENING.md).

$ErrorActionPreference = "Stop"
$Source = "C:\Dev\MSSP\app.db"
# Prefer second drive; fall back to local backups folder
$DestRoot = if (Test-Path "D:\BoundryBackups") { "D:\BoundryBackups" } else { "C:\Dev\MSSP\backups" }
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$DestDir = Join-Path $DestRoot "appdb"
New-Item -ItemType Directory -Force -Path $DestDir | Out-Null

if (-not (Test-Path $Source)) {
  Write-Error "Source DB missing: $Source"
  exit 1
}

$Dest = Join-Path $DestDir "app_$Stamp.db"
Copy-Item -LiteralPath $Source -Destination $Dest -Force
Write-Host "Backed up to $Dest"

# Keep last 14 copies
Get-ChildItem $DestDir -Filter "app_*.db" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -Skip 14 |
  Remove-Item -Force -ErrorAction SilentlyContinue
