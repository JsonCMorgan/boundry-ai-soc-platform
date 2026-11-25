"""Multi-tenant helpers: MSSP client_id slugs, SIEM filters, syslog source map."""

from __future__ import annotations

import re
from typing import Any, Callable

DbFetchone = Callable[..., dict | None]
DbRun = Callable[..., None]


def slug_from_username(username: str) -> str:
    """Derive a stable tenant slug from a client username."""
    s = re.sub(r"[^a-z0-9]+", "-", (username or "").lower().strip()).strip("-")
    return (s[:50] if s else "client")


def ensure_tenant(
    db_run: DbRun,
    db_fetchone: DbFetchone,
    ph: str,
    user_id: int,
    username: str,
    display_name: str = "",
    tier: str = "Silver",
    is_practice: int = 0,
) -> str:
    """Create or update mssp_tenants row for a client user; return client_id slug."""
    slug = slug_from_username(username)
    existing = db_fetchone(
        f"SELECT client_id, user_id FROM mssp_tenants WHERE user_id = {ph}",
        (user_id,),
    )
    if existing:
        return existing["client_id"]

    by_slug = db_fetchone(
        f"SELECT client_id, user_id FROM mssp_tenants WHERE client_id = {ph}",
        (slug,),
    )
    if by_slug:
        db_run(
            f"UPDATE mssp_tenants SET user_id = {ph}, display_name = {ph}, tier = {ph}, "
            f"is_practice = {ph} WHERE client_id = {ph}",
            (user_id, display_name or username, tier, is_practice, slug),
        )
        return slug

    db_run(
        f"INSERT INTO mssp_tenants (client_id, display_name, tier, is_practice, user_id) "
        f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph})",
        (slug, display_name or username, tier, is_practice, user_id),
    )
    return slug


def resolve_tenant_slug(db_fetchone: DbFetchone, ph: str, user_id: int | None) -> str:
    """Map users.id to mssp_tenants.client_id text slug."""
    if not user_id:
        return "boundry_self"
    row = db_fetchone(
        f"SELECT client_id FROM mssp_tenants WHERE user_id = {ph}",
        (user_id,),
    )
    if row:
        return row["client_id"]
    u = db_fetchone(f"SELECT username FROM users WHERE id = {ph}", (user_id,))
    return slug_from_username(u["username"]) if u else "boundry_self"


def resolve_user_id_from_slug(db_fetchone: DbFetchone, ph: str, client_slug: str) -> int | None:
    """Inverse lookup for client-facing queries by tenant slug."""
    row = db_fetchone(
        f"SELECT user_id FROM mssp_tenants WHERE client_id = {ph}",
        (client_slug,),
    )
    if row and row.get("user_id"):
        return int(row["user_id"])
    return None


def tenant_is_practice(db_fetchone: DbFetchone, ph: str, client_slug: str) -> bool:
    """True when tenant is a Practice drill client."""
    row = db_fetchone(
        f"SELECT is_practice FROM mssp_tenants WHERE client_id = {ph}",
        (client_slug,),
    )
    return bool(row and int(row.get("is_practice") or 0))


def tenant_filter_sql(
    tenant: str | None, ph: str, column: str = "client_id", *, prefix: str = " AND "
) -> tuple[str, tuple[Any, ...]]:
    """SQL suffix + params for tenant-scoped analyst views (GAP-003)."""
    if not tenant:
        return "", ()
    return f"{prefix}{column} = {ph}", (tenant,)


def siem_tenant_clause(
    tenant: str | None, ph: str, column: str = "client_id"
) -> tuple[str, tuple[Any, ...]]:
    """Backward-compatible alias for SIEM list filters."""
    return tenant_filter_sql(tenant, ph, column)


def list_tenants_for_picker(db_fetchall: Callable[..., list]) -> list[dict[str, Any]]:
    """Tenant dropdown rows: slug, display_name, is_practice."""
    rows = db_fetchall(
        "SELECT client_id, display_name, tier, is_practice, user_id "
        "FROM mssp_tenants ORDER BY display_name ASC, client_id ASC"
    ) or []
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "client_id": r.get("client_id") or "",
                "display_name": r.get("display_name") or r.get("client_id") or "",
                "tier": r.get("tier") or "",
                "is_practice": int(r.get("is_practice") or 0),
            }
        )
    return out


def sync_analyst_tenant_from_request(
    request_tenant: str | None, session: dict[str, Any]
) -> str | None:
    """Persist ?tenant= on analyst session; __all__ clears filter."""
    if session.get("role") != "analyst":
        return None
    raw = (request_tenant or "").strip()
    if raw == "__all__":
        session.pop("analyst_tenant", None)
        return None
    if raw:
        session["analyst_tenant"] = raw
        return raw
    saved = (session.get("analyst_tenant") or "").strip()
    return saved or None


def resolve_syslog_client(
    db_fetchone: DbFetchone, ph: str, src_ip: str
) -> str | None:
    """Look up syslog_sources table; None if unregistered."""
    row = db_fetchone(
        f"SELECT client_id FROM syslog_sources WHERE src_ip = {ph} AND enabled = 1",
        (src_ip,),
    )
    return row["client_id"] if row else None


def risk_map_by_user_id(db_fetchall: Callable[..., list]) -> dict:
    """Control Room chips: user_id -> grade / monthly from risk_assessments."""
    rows = db_fetchall(
        """
        SELECT r.client_id AS user_id, r.grade, r.recommended_monthly
        FROM risk_assessments r
        """
    )
    colors = {"A": "#00b432", "B": "#8fce00", "C": "#ff9900", "D": "#ff6a00", "F": "#ff4444"}
    out: dict = {}
    for r in rows or []:
        uid = r.get("user_id")
        grade = r.get("grade") or ""
        out[uid] = {
            "grade": grade,
            "recommended_monthly": r.get("recommended_monthly"),
            "color": colors.get(grade, "#888"),
        }
    return out