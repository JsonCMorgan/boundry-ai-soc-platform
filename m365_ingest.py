"""Microsoft 365 / Entra unified audit JSON → SIEM events (Phase 1 manual upload)."""

from __future__ import annotations

import json
from typing import Any, Callable


def _record_operation(record: dict) -> tuple[str, str, str]:
    """Map one audit record to (event_type, severity, description)."""
    op = (record.get("Operation") or record.get("operation") or "").strip()
    op_lower = op.lower()
    user = (
        record.get("UserId")
        or record.get("userPrincipalName")
        or record.get("UserType")
        or ""
    )
    if "fail" in op_lower or "locked" in op_lower:
        return "m365_signin_failed", "MEDIUM", f"M365 {op} — {user}"
    if "consent" in op_lower or "application" in op_lower:
        return "vendor_app_consent", "HIGH", f"M365 {op} — {user}"
    if "download" in op_lower or "export" in op_lower:
        return "file_download_anomaly", "MEDIUM", f"M365 {op} — {user}"
    if "impossible" in op_lower or "anomalous" in op_lower:
        return "m365_impossible_travel", "HIGH", f"M365 {op} — {user}"
    return "m365_audit", "INFO", f"M365 {op} — {user}"


def parse_audit_payload(payload: Any) -> list[dict]:
    """Accept list or {\"value\": [...]} Graph style body."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        if isinstance(payload.get("value"), list):
            return [r for r in payload["value"] if isinstance(r, dict)]
        if payload.get("Operation") or payload.get("operation"):
            return [payload]
    return []


def ingest_m365_records(
    records: list[dict],
    client_id: str,
    ingest_fn: Callable[..., None],
) -> int:
    """Write normalized records via siem_collector.ingest_event. Returns count."""
    n = 0
    for rec in records:
        etype, sev, desc = _record_operation(rec)
        eid = str(rec.get("Id") or rec.get("id") or n)[:80]
        ingest_fn(
            source="m365_audit",
            event_id=eid,
            event_type=etype,
            severity=sev,
            host="m365",
            user=str(rec.get("UserId") or "")[:120],
            description=desc[:500],
            raw=rec,
            client_id=client_id,
            correlate=True,
        )
        n += 1
    return n