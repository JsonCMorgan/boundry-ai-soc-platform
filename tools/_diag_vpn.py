"""One-shot VPN detection diagnostic."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import time

HEARTBEAT = r"C:\ProgramData\NordVPN\connections\vpn_state_heartbeat.db"
DOTNET_EPOCH = 621355968000000000
VPN_STATES = {0: "Disconnected", 1: "Connecting", 2: "Connected", 3: "Disconnecting", 4: "Error"}

print("heartbeat exists:", os.path.exists(HEARTBEAT))
if os.path.exists(HEARTBEAT):
    try:
        conn = sqlite3.connect(HEARTBEAT, timeout=3)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT VpnState, TimestampUtc FROM VpnStateHeartbeatHistory ORDER BY Id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            unix_ts = (row["TimestampUtc"] - DOTNET_EPOCH) / 10_000_000
            age = time.time() - unix_ts
            print(
                "VpnState:",
                row["VpnState"],
                VPN_STATES.get(row["VpnState"]),
                "age_s:",
                round(age, 1),
            )
        else:
            print("heartbeat row: empty")
    except Exception as exc:
        print("heartbeat read error:", type(exc).__name__, exc)
        try:
            conn = sqlite3.connect(f"file:{HEARTBEAT}?mode=ro", uri=True, timeout=3)
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT VpnState, TimestampUtc FROM VpnStateHeartbeatHistory ORDER BY Id DESC LIMIT 1"
            ).fetchone()
            conn.close()
            print("uri mode row:", dict(row) if row else None)
        except Exception as exc2:
            print("uri mode also failed:", type(exc2).__name__, exc2)

ps_path = os.path.join(os.path.dirname(__file__), "_diag_vpn_adapters.ps1")
with open(ps_path, "w", encoding="utf-8") as f:
    f.write(
        "Get-NetAdapter | ForEach-Object {\n"
        "  $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)\n"
        "  Write-Output (\"{0}`t{1}`t{2}`t{3}\" -f $_.Name, $_.Status, $_.InterfaceDescription, $ip)\n"
        "}\n"
        "Write-Output '---NORDLYNX---'\n"
        "$a = Get-NetAdapter -Name 'NordLynx' -ErrorAction SilentlyContinue\n"
        "$ip = (Get-NetIPAddress -InterfaceAlias 'NordLynx' -AddressFamily IPv4 "
        "-ErrorAction SilentlyContinue).IPAddress\n"
        "Write-Output (\"{0}|{1}\" -f $a.Status, $ip)\n"
    )

out = subprocess.check_output(
    ["powershell", "-NonInteractive", "-NoProfile", "-File", ps_path],
    timeout=20,
).decode("utf-8", errors="replace")
print("--- adapters ---")
for line in out.splitlines():
    low = line.lower()
    if "nordlynx" in low or "nord" in low or "wireguard" in low or "wintun" in low or "tap" in low or line.startswith("---"):
        print(line)
print("--- raw nordlynx / tail ---")
print("\n".join(out.splitlines()[-5:]))
