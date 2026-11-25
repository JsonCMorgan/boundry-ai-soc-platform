# Boundry.AI — daily app.db backup (M6)
# Copies C:\Dev\MSSP\app.db to a dated file on a second drive (or fallback folder).
# Register with Task Scheduler (see docs/PRE_CLIENT_HARDENING.md).
# Use -Verify to open the copy with sqlite3 and require core tables (GAP-011).

param(
  [switch]$Verify
)

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

if ($Verify) {
  $sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
  if (-not $sqlite) {
    Write-Error "sqlite3 not on PATH — install SQLite tools or skip -Verify"
    exit 2
  }
  $tables = @("users", "siem_events", "reports", "mssp_tenants")
  foreach ($t in $tables) {
    $n = & sqlite3 $Dest "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='$t';"
    if ($n -ne "1") {
      Write-Error "Verify failed: missing table $t in $Dest"
      exit 3
    }
  }
  Write-Host "Verify OK ($($tables -join ', '))"
}

# Keep last 14 copies
Get-ChildItem $DestDir -Filter "app_*.db" |
  Sort-Object LastWriteTime -Descending |
  Select-Object -Skip 14 |
  Remove-Item -Force -ErrorAction SilentlyContinue
