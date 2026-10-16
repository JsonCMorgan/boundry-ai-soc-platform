New-NetFirewallRule -DisplayName 'BoundryAI Allow Cafe Quiz 8765' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8765 -Profile Private,Domain -Enabled True | Out-Null
'FW_OK'
