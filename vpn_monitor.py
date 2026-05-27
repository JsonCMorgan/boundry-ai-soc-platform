"""
VPN Monitor — Boundry.AI
========================
Monitors NordVPN connection state and injects SIEM events when VPN
drops unexpectedly.  Reads from three local sources — no outbound
calls, no NordVPN CLI required:

  1. NordLynx network adapter   — primary connected/disconnected flag
  2. vpn_state_heartbeat.db     — VpnState enum (0=Disconnected, 2=Connected)
  3. settings.db                — kill switch + split-tunnel settings

Status is exposed via get_vpn_status() for the dashboard widget and
polled by the /api/vpn/status Flask route.
"""

import os
import time
import sqlite3
import logging
import threading
import subprocess
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger("vpn_monitor")

# ── Paths ─────────────────────────────────────────────────────────────────────
_HEARTBEAT_DB = r"C:\ProgramData\NordVPN\connections\vpn_state_heartbeat.db"
_SETTINGS_DB  = r"C:\ProgramData\NordVPN\settings.db"

# .NET ticks → Unix epoch offset (100-ns intervals from 0001-01-01 to 1970-01-01)
_DOTNET_EPOCH = 621355968000000000

# VpnState enum values (from heartbeat DB)
_VPN_STATES = {
    0: "Disconnected",
    1: "Connecting",
    2: "Connected",
    3: "Disconnecting",
    4: "Error",
}

POLL_INTERVAL = 30   # seconds between status checks
ALERT_COOLDOWN = 300  # seconds before re-alerting on the same condition

# ── Module state ──────────────────────────────────────────────────────────────
_db_run:      Callable | None = None
_db_fetchall: Callable | None = None
_ph:          str = "?"
_started:     bool = False
_last_alert:  float = 0.0   # unix timestamp of last SIEM alert

_status: dict = {
    "available":      False,   # NordVPN installed?
    "connected":      False,
    "vpn_state":      "Unknown",
    "vpn_ip":         None,
    "kill_switch":    False,
    "split_tunnel":   False,
    "last_checked":   None,
    "last_connected": None,    # ISO timestamp of last confirmed connection
    "last_dropped":   None,    # ISO timestamp of last disconnect event
    "error":          None,
    "heartbeat_age_s": None,   # seconds since last NordVPN heartbeat
}


# ── Public API ────────────────────────────────────────────────────────────────

def start(db_run_fn: Callable, db_fetchall_fn: Callable, ph: str = "?") -> None:
    """Initialise and launch the background monitor thread."""
    global _db_run, _db_fetchall, _ph, _started

    if _started:
        return
    _started = True
    _db_run      = db_run_fn
    _db_fetchall = db_fetchall_fn
    _ph          = ph

    # Check NordVPN is installed before starting
    if not os.path.exists(_HEARTBEAT_DB):
        log.info("[vpn] NordVPN heartbeat DB not found — monitor disabled")
        _status["available"] = False
        return

    _status["available"] = True

    # Do an immediate synchronous read so the dashboard shows real data on first load
    # (background thread would otherwise wait POLL_INTERVAL before first update)
    try:
        _do_poll(prev_connected=None)
    except Exception as exc:
        log.debug(f"[vpn] Initial poll error (non-fatal): {exc}")

    t = threading.Thread(target=_monitor_loop, name="vpn-monitor", daemon=True)
    t.start()
    log.info(f"[vpn] VPN monitor started — connected={_status['connected']}")


def get_vpn_status() -> dict:
    """Return a snapshot of VPN status (safe for JSON serialisation)."""
    return dict(_status)


# ── Internal ──────────────────────────────────────────────────────────────────

def _read_heartbeat() -> tuple[int, float]:
    """
    Read the most recent VpnState from the heartbeat DB.
    Returns (vpn_state_int, heartbeat_age_seconds).
    """
    try:
        conn = sqlite3.connect(f"file:{_HEARTBEAT_DB}?mode=ro", uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT VpnState, TimestampUtc FROM VpnStateHeartbeatHistory ORDER BY Id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            # Convert .NET ticks to Unix epoch
            unix_ts = (row["TimestampUtc"] - _DOTNET_EPOCH) / 10_000_000
            age_s   = time.time() - unix_ts
            return int(row["VpnState"]), round(age_s, 1)
    except Exception as exc:
        log.debug(f"[vpn] heartbeat read error: {exc}")
    return -1, -1.0


def _read_settings() -> dict:
    """Read kill switch + split tunnel state from settings.db."""
    result = {"kill_switch": False, "split_tunnel": False}
    try:
        conn = sqlite3.connect(f"file:{_SETTINGS_DB}?mode=ro", uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT Key, Value FROM Settings WHERE Key IN "
            "('KillSwitch:IsEnabled','InternetKillSwitch:IsEnabled','SplitTunneling:IsEnabled')"
        ).fetchall()
        conn.close()
        for r in rows:
            k, v = r["Key"], r["Value"].lower() == "true"
            if "KillSwitch" in k:
                result["kill_switch"] = result["kill_switch"] or v
            elif "SplitTunneling" in k:
                result["split_tunnel"] = v
    except Exception as exc:
        log.debug(f"[vpn] settings read error: {exc}")
    return result


def _read_adapter() -> tuple[bool, str | None]:
    """
    Check NordLynx adapter state via PowerShell.
    Returns (is_up: bool, vpn_ip: str | None).
    Fast path: subprocess call, sub-100ms on local machine.
    """
    try:
        ps_script = (
            "$a = Get-NetAdapter -Name 'NordLynx' -ErrorAction SilentlyContinue; "
            "$ip = (Get-NetIPAddress -InterfaceAlias 'NordLynx' -AddressFamily IPv4 "
            "       -ErrorAction SilentlyContinue).IPAddress; "
            "Write-Output \"$($a.Status)|$ip\""
        )
        out = subprocess.check_output(
            ["powershell", "-NonInteractive", "-NoProfile", "-Command", ps_script],
            timeout=8,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="replace").strip()

        parts = out.split("|")
        status_str = parts[0].strip() if parts else ""
        ip_val     = parts[1].strip() if len(parts) > 1 else None
        is_up      = status_str.lower() == "up"
        return is_up, (ip_val if ip_val and ip_val != "" else None)
    except Exception as exc:
        log.debug(f"[vpn] adapter read error: {exc}")
        return False, None


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _inject_siem_event(event_type: str, severity: str, description: str) -> None:
    """Write a VPN state change event to the SIEM stream."""
    if _db_run is None:
        return
    try:
        _db_run(
            f"""INSERT INTO siem_events
                (source, event_id, event_type, severity, host, description, raw, created_at)
                VALUES ({_ph},{_ph},{_ph},{_ph},{_ph},{_ph},{_ph}, datetime('now'))""",
            (
                "vpn_monitor", "VPN", event_type, severity,
                "localhost", description,
                '{"source": "vpn_monitor"}',
            ),
        )
    except Exception as exc:
        log.error(f"[vpn] SIEM inject failed: {exc}")


def _do_poll(prev_connected: bool | None) -> bool | None:
    """
    Single poll cycle: read all sources, update _status, fire SIEM alerts.
    Returns the new connected state (for the loop to track previous state).
    """
    global _last_alert

    now = _now_iso()

    # 1. Read adapter (primary connection indicator)
    adapter_up, vpn_ip = _read_adapter()

    # 2. Read heartbeat DB (secondary confirmation)
    vpn_state_int, hb_age = _read_heartbeat()
    vpn_state_name = _VPN_STATES.get(vpn_state_int, f"Unknown({vpn_state_int})")

    # Reconcile: connected if adapter is up AND VpnState == 2
    # (prevents false positives during server switches where adapter briefly flaps)
    connected = adapter_up and vpn_state_int == 2

    # 3. Settings
    settings = _read_settings()

    # 4. Update shared status dict
    _status.update({
        "available":       True,
        "connected":       connected,
        "vpn_state":       vpn_state_name,
        "vpn_ip":          vpn_ip,
        "kill_switch":     settings["kill_switch"],
        "split_tunnel":    settings["split_tunnel"],
        "last_checked":    now,
        "error":           None,
        "heartbeat_age_s": hb_age if hb_age >= 0 else None,
    })

    if connected:
        _status["last_connected"] = now

    # 5. State-change alerts (only when SIEM DB is available)
    if _db_run is not None:
        cooldown_elapsed = (time.time() - _last_alert) > ALERT_COOLDOWN

        if prev_connected is True and not connected:
            _status["last_dropped"] = now
            _inject_siem_event(
                event_type="vpn_disconnected",
                severity="CRITICAL",
                description=(
                    f"NordVPN connection dropped — client traffic may be UNENCRYPTED. "
                    f"NordLynx: {'Up' if adapter_up else 'Down'} · "
                    f"VpnState: {vpn_state_name} · "
                    f"Kill switch: {'ACTIVE' if settings['kill_switch'] else 'OFF (traffic exposed)'}"
                ),
            )
            _last_alert = time.time()
            log.warning("[vpn] VPN DISCONNECTED — SIEM alert fired")

        elif prev_connected is False and connected:
            _inject_siem_event(
                event_type="vpn_connected",
                severity="INFO",
                description=(
                    f"NordVPN connection established. "
                    f"VPN IP: {vpn_ip or 'unknown'} · VpnState: {vpn_state_name}"
                ),
            )
            log.info(f"[vpn] VPN connected — IP {vpn_ip}")

        elif not connected and cooldown_elapsed and prev_connected is not None:
            _inject_siem_event(
                event_type="vpn_disconnected",
                severity="HIGH",
                description=(
                    f"NordVPN still disconnected — reminder alert. "
                    f"Kill switch: {'ON' if settings['kill_switch'] else 'OFF'}"
                ),
            )
            _last_alert = time.time()

    return connected


def _monitor_loop() -> None:
    """Main loop: poll every POLL_INTERVAL seconds, track state changes."""
    prev_connected: bool | None = _status.get("connected")  # seed from initial read

    while True:
        time.sleep(POLL_INTERVAL)
        try:
            prev_connected = _do_poll(prev_connected)
        except Exception as exc:
            _status["error"]        = str(exc)
            _status["last_checked"] = _now_iso()
            log.error(f"[vpn] Monitor error: {exc}")
