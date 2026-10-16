$ErrorActionPreference = "Continue"
$log = @()
try {
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $false -Force
  $log += "SMB1+SMB2 server protocols DISABLED"
} catch { $log += "SMB_CONFIG_FAIL: $($_.Exception.Message)" }

# Disable NetBIOS over TCP/IP on all adapters (2 = Disable)
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object {
  Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 -ErrorAction SilentlyContinue
}
$log += "NetBIOS NetbiosOptions=2 on all adapters"

# Restart NetBT / related if possible
Restart-Service lmhosts -Force -ErrorAction SilentlyContinue
$log += "lmhosts restarted"

# Confirm
$smb = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
$log += "EnableSMB1=$($smb.EnableSMB1Protocol) EnableSMB2=$($smb.EnableSMB2Protocol)"
$log += (Get-Service LanmanServer | ForEach-Object { "LanmanServer $($_.Status)/$($_.StartType)" })
$log += "---LISTEN---"
$log += (netstat -ano | Select-String "LISTENING" | Select-String ":135 |:139 |:445 |:8080 ").Line
$log | Set-Content "C:\Dev\MSSP\tools\_harden_smb2_result.txt" -Encoding UTF8
$log | ForEach-Object { $_ }
