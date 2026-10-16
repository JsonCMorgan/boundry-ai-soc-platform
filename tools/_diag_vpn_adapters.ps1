Get-NetAdapter | ForEach-Object {
  $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)
  Write-Output ("{0}`t{1}`t{2}`t{3}" -f $_.Name, $_.Status, $_.InterfaceDescription, $ip)
}
Write-Output '---NORDLYNX---'
$a = Get-NetAdapter -Name 'NordLynx' -ErrorAction SilentlyContinue
$ip = (Get-NetIPAddress -InterfaceAlias 'NordLynx' -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
Write-Output ("{0}|{1}" -f $a.Status, $ip)
