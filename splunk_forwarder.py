"""
Splunk HEC Forwarder — Boundry.AI SIEM
=======================================
Forwards siem_events rows to a Splunk HTTP Event Collector endpoint.
Runs as a background daemon thread alongside the SIEM collectors.

Configuration (environment variables):
  SPLUNK_HEC_URL    HEC base URL   (default: http://localhost:8088)
  SPLUNK_HEC_TOKEN  HEC token      (required to enable forwarding)
  SPLUNK_INDEX      Target index   (default: main)

Usage:
  import splunk_forwarder
  splunk_forwarder.start(db_run_fn=db_run, db_fetchall_fn=db_fetchall)

The forwarder is a no-op (silent) when SPLUNK_HEC_TOKEN is not set, so it's
safe to import and start unconditionally — nothing breaks if Splunk isn't up.

High-water mark is persisted in the splunk_forwarder_state DB table so events
are not re-sent after an app restart, even if Splunk was temporarily offline.

Splunk HEC docs: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
"""

import os
import json
import time
import logging
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger("splunk_forwarder")

# ── Configuration ─────────────────────────────────────────────────────────────
HEC_URL    = os.environ.get("SPLUNK_HEC_URL", "http://localhost:8088").rstrip("/")
HEC_TOKEN  = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
HEC_INDEX  = os.environ.get("SPLUNK_INDEX", "main")
HEC_SOURCE = "boundry-ai"
HEC_SOURCETYPE = "boundry:siem"

# How many events to batch per POST
BATCH_SIZE   = 50
# Polling interval when Splunk is reachable
POLL_INTERVAL = 30  # seconds
# Back-off when Splunk is down (avoids log spam)
BACKOFF_MAX  = 300  # 5 minutes

# ── Module-level state ────────────────────────────────────────────────────────
_db_run: Callable | None = None
_db_fetchall: Callable | None = None
_ph: str = "?"
_started = False
_status: dict = {
    "enabled": False,
    "connected": False,
    "last_attempt": None,
    "last_success": None,
    "events_forwarded": 0,
    "last_error": None,
    "hec_url": HEC_URL,
}


# ── Public API ────────────────────────────────────────────────────────────────

def start(db_run_fn: Callable, db_fetchall_fn: Callable, ph: str = "?") -> None:
    """
    Initialise and start the background forwarder thread.
    Call once at Flask startup, after init_db().
    """
    global _db_run, _db_fetchall, _ph, _started

    if _started:
        return
    _started = True

    _db_run      = db_run_fn
    _db_fetchall = db_fetchall_fn
    _ph          = ph

    _ensure_state_table()

    if not HEC_TOKEN:
        log.info("[splunk] SPLUNK_HEC_TOKEN not set — forwarder disabled (set it to enable)")
        _status["enabled"] = False
        return

    _status["enabled"] = True
    _status["hec_url"] = HEC_URL

    t = threading.Thread(target=_forward_loop, name="splunk-forwarder", daemon=True)
    t.start()
    log.info(f"[splunk] Forwarder started → {HEC_URL}  index={HEC_INDEX}")


def get_status() -> dict:
    """Return a copy of the forwarder status (safe for JSON serialisation)."""
    return dict(_status)


def set_token(token: str) -> bool:
    """
    Hotload a new HEC token without restarting Flask.
    Returns True if the thread was (re)started, False if already running.
    """
    global HEC_TOKEN
    token = token.strip()

    # Validate the token before storing.  Splunk HEC tokens are UUIDs or short
    # alphanumeric strings — they must never contain control characters (CR, LF,
    # NUL, etc.) because the token is placed verbatim in an HTTP Authorization
    # header ("Splunk <token>"). A newline inside the value would allow an
    # attacker to inject arbitrary HTTP headers into every outbound HEC request.
    if not token:
        log.warning("[splunk] set_token: empty token rejected")
        return False
    if any(ord(c) < 32 for c in token):
        log.warning("[splunk] set_token: token rejected — contains control characters")
        return False
    if len(token) > 512:
        log.warning("[splunk] set_token: token rejected — exceeds 512-character limit")
        return False

    HEC_TOKEN = token
    os.environ["SPLUNK_HEC_TOKEN"] = HEC_TOKEN
    _status["enabled"] = bool(HEC_TOKEN)

    if HEC_TOKEN and not _status["connected"]:
        # Kick off the thread if it's not running
        t = threading.Thread(target=_forward_loop, name="splunk-forwarder", daemon=True)
        t.start()
        return True
    return False


# ── Internal ──────────────────────────────────────────────────────────────────

def _ensure_state_table() -> None:
    """Create the high-water mark table if it doesn't exist."""
    _db_run("""
        CREATE TABLE IF NOT EXISTS splunk_forwarder_state (
            id           INTEGER PRIMARY KEY CHECK (id = 1),
            last_sent_id INTEGER NOT NULL DEFAULT 0,
            updated_at   TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)
    # Seed the single state row
    rows = _db_fetchall("SELECT id FROM splunk_forwarder_state")
    if not rows:
        _db_run("INSERT INTO splunk_forwarder_state (id, last_sent_id) VALUES (1, 0)")


def _get_hwm() -> int:
    """Read the highest already-forwarded event ID."""
    rows = _db_fetchall("SELECT last_sent_id FROM splunk_forwarder_state WHERE id = 1")
    return rows[0]["last_sent_id"] if rows else 0


def _set_hwm(event_id: int) -> None:
    """Persist the new high-water mark."""
    _db_run(
        f"UPDATE splunk_forwarder_state SET last_sent_id = {_ph}, updated_at = datetime('now') WHERE id = 1",
        (event_id,),
    )


def _fetch_pending(hwm: int) -> list[dict]:
    """Return up to BATCH_SIZE events with id > hwm, oldest first."""
    return _db_fetchall(
        f"""SELECT id, created_at, source, event_id, event_type, severity,
                   host, user_account, src_ip, dst_ip, description, raw
            FROM siem_events
            WHERE id > {_ph}
            ORDER BY id ASC
            LIMIT {_ph}""",
        (hwm, BATCH_SIZE),
    )


def _to_epoch(ts_str: str) -> float:
    """Convert a SQLite datetime string to a Unix epoch float for Splunk."""
    if not ts_str:
        return time.time()
    try:
        # Handle both "2026-05-27 14:23:01" and ISO "2026-05-27T14:23:01"
        ts_str = ts_str.replace("T", " ").split(".")[0]
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return time.time()


def _build_hec_payload(events: list[dict]) -> bytes:
    """
    Build a Splunk HEC batch payload.
    Each event is a separate JSON object on its own line (HEC batch format).
    https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector#Event_data
    """
    lines = []
    for ev in events:
        # Parse raw field if it's a JSON string
        raw = ev.get("raw", {})
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {"raw": raw}

        event_body = {
            "event_id":    ev.get("event_id", ""),
            "event_type":  ev.get("event_type", ""),
            "severity":    ev.get("severity", "INFO"),
            "source":      ev.get("source", ""),
            "host":        ev.get("host", ""),
            "user_account": ev.get("user_account", ""),
            "src_ip":      ev.get("src_ip", ""),
            "dst_ip":      ev.get("dst_ip", ""),
            "description": ev.get("description", ""),
            "boundry_id":  ev.get("id"),
            **raw,
        }

        hec_event = {
            "time":       _to_epoch(ev.get("created_at", "")),
            "host":       ev.get("host") or "boundry-ai-host",
            "source":     HEC_SOURCE,
            "sourcetype": HEC_SOURCETYPE,
            "index":      HEC_INDEX,
            "event":      event_body,
        }
        lines.append(json.dumps(hec_event))

    return "\n".join(lines).encode("utf-8")


def _post_to_splunk(payload: bytes) -> bool:
    """
    POST a batch payload to the Splunk HEC endpoint.
    Returns True on success (HTTP 200), False otherwise.
    """
    url = f"{HEC_URL}/services/collector/event"
    headers = {
        "Authorization": f"Splunk {HEC_TOKEN}",
        "Content-Type":  "application/json",
    }
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            if body.get("code") == 0:
                return True
            log.warning(f"[splunk] HEC returned non-zero: {body}")
            _status["last_error"] = str(body)
            return False
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")[:200]
        log.warning(f"[splunk] HEC HTTP {exc.code}: {body_text}")
        _status["last_error"] = f"HTTP {exc.code}: {body_text}"
        return False
    except (urllib.error.URLError, OSError) as exc:
        # Splunk is down — this is expected until it's installed
        _status["last_error"] = str(exc)
        return False


def _forward_loop() -> None:
    """
    Main loop: poll → batch → POST → advance HWM → sleep.
    Backs off exponentially when Splunk is unreachable.
    """
    backoff = POLL_INTERVAL

    while True:
        _status["last_attempt"] = datetime.utcnow().isoformat()

        try:
            hwm     = _get_hwm()
            pending = _fetch_pending(hwm)

            if pending:
                payload     = _build_hec_payload(pending)
                success     = _post_to_splunk(payload)

                if success:
                    new_hwm = pending[-1]["id"]
                    _set_hwm(new_hwm)
                    count = len(pending)
                    _status["events_forwarded"] += count
                    _status["connected"]   = True
                    _status["last_success"] = datetime.utcnow().isoformat()
                    _status["last_error"]  = None
                    log.info(f"[splunk] Forwarded {count} events (hwm now {new_hwm})")
                    backoff = POLL_INTERVAL  # reset on success
                else:
                    _status["connected"] = False
                    backoff = min(backoff * 2, BACKOFF_MAX)
            else:
                # Nothing pending — normal state when caught up
                if _status["connected"]:
                    log.debug("[splunk] No new events to forward")

        except Exception as exc:
            log.error(f"[splunk] Forwarder error: {exc}")
            _status["last_error"] = str(exc)
            _status["connected"]  = False
            backoff = min(backoff * 2, BACKOFF_MAX)

        time.sleep(backoff)
