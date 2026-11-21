# Mirror Professor Messer pack into content/private/messer (gitignored).
# Run from Explorer with OneDrive signed in; use "Always keep on this device" on the folder first.

$ErrorActionPreference = "Continue"
$src = "C:\Users\ricka\OneDrive\Documents\Cyber Security Course\Professor Messer Security Plus"
$dst = "C:\Dev\MSSP\content\private\messer"

if (-not (Test-Path $src)) {
    Write-Error "Source not found: $src"
    exit 1
}
New-Item -ItemType Directory -Force -Path $dst | Out-Null

# /COPY:DAT skips security/owner/audit (fewer ERROR 5 on OneDrive placeholders)
robocopy $src $dst /E /XO /R:2 /W:2 /COPY:DAT /DCOPY:DA /NFL /NDL /NJH /NJS /nc /ns /np
$code = $LASTEXITCODE
Write-Host "Robocopy exit code: $code (0-7 = success with notes; 8+ = copy failures)"
if ($code -ge 8) { exit $code }
exit 0
