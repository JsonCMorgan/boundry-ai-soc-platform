"""Analyst audit trail and ingest API key resolution (grace rotation)."""

from __future__ import annotations

import hmac
import secrets
from typing import Any, Callable

DbFetchone = Callable[..., dict | None]
DbRun = Callable[..., None]


def log_analyst_audit(
    db_run: DbRun,
    ph: str,
    *,
    analyst_id: int | None,
    action: str,
    detail: str = "",
    target_user_id: int | None = None,
    ref_id: str = "",
) -> None:
    """Append one row to analyst_audit (GAP-025)."""
    db_run(
        f"INSERT INTO analyst_audit (analyst_id, action, detail, target_user_id, ref_id) "
        f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph})",
        (
            analyst_id,
            (action or "")[:80],
            (detail or "")[:500],
            target_user_id,
            (ref_id or "")[:120],
        ),
    )


def resolve_ingest_api_key(db_fetchone: DbFetchone, ph: str, api_key: str) -> dict | None:
    """Resolve X-API-Key to user row; honors 24h grace after rotation (GAP-024)."""
    if not api_key:
        return None
    row = db_fetchone(
        f"SELECT id, username, role, api_key, api_key_grace, api_key_grace_until "
        f"FROM users WHERE api_key = {ph}",
        (api_key,),
    )
    if row and hmac.compare_digest(api_key.encode(), (row.get("api_key") or "").encode()):
        return row
    grace_row = db_fetchone(
        f"SELECT id, username, role, api_key, api_key_grace, api_key_grace_until "
        f"FROM users WHERE api_key_grace = {ph} "
        f"AND api_key_grace_until IS NOT NULL AND api_key_grace_until > datetime('now')",
        (api_key,),
    )
    if grace_row and hmac.compare_digest(
        api_key.encode(), (grace_row.get("api_key_grace") or "").encode()
    ):
        return grace_row
    return None


def rotate_client_api_key(
    db_run: DbRun,
    db_fetchone: DbFetchone,
    ph: str,
    client_user_id: int,
) -> dict[str, Any]:
    """Issue new api_key; previous key valid until api_key_grace_until."""
    row = db_fetchone(
        f"SELECT id, username, api_key FROM users WHERE id = {ph} AND role = 'client'",
        (client_user_id,),
    )
    if not row:
        return {"ok": False, "error": "Client not found"}
    old_key = row.get("api_key") or ""
    new_key = secrets.token_urlsafe(32)
    db_run(
        f"UPDATE users SET api_key = {ph}, api_key_grace = {ph}, "
        f"api_key_grace_until = datetime('now', '+24 hours') WHERE id = {ph}",
        (new_key, old_key, client_user_id),
    )
    grace = db_fetchone(
        f"SELECT api_key_grace_until FROM users WHERE id = {ph}", (client_user_id,)
    )
    return {
        "ok": True,
        "api_key": new_key,
        "grace_until": (grace or {}).get("api_key_grace_until") or "",
        "username": row.get("username") or "",
    }