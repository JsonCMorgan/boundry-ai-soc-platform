$c = Get-SmbServerConfiguration
@(
  "EnableSMB1Protocol=$($c.EnableSMB1Protocol)"
  "EnableSMB2Protocol=$($c.EnableSMB2Protocol)"
  (Get-Service LanmanServer | ForEach-Object { "LanmanServer=$($_.Status)/$($_.StartType)" })
  (driverquery | Select-String -Pattern 'srv' | ForEach-Object { $_.Line })
) | Set-Content 'C:\Dev\MSSP\tools\_check_smb_out.txt'
