@echo off
rem Requests UAC elevation, then applies Boundry firewall + SMB hardening.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','C:\Dev\MSSP\tools\_harden_ports_option_a.ps1','-StayOpen')"
