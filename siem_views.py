"""
SIEM Log Activity helpers: saved searches, detections list, event grouping.
"""

from __future__ import annotations

from typing import Any, Callable


def list_saved_searches(db_fetchall: Callable, analyst_id: int, *, ph: str = "?") -> list[dict[str, Any]]:
    """Return saved searches for an analyst."""
    rows = db_fetchall(
        f"SELECT id, name, query_json, created_at FROM siem_saved_searches "
        f"WHERE analyst_id = {ph} ORDER BY id DESC",
        (analyst_id,),
    )
    return [dict(r) for r in rows]


def create_saved_search(
    db_run: Callable,
    db_fetchone: Callable,
    analyst_id: int,
    name: str,
    query_json: str,
    *,
    ph: str = "?",
) -> dict[str, Any]:
    """Insert a saved search."""
    name = (name or "").strip()[:120]
    if len(name) < 2:
        return {"ok": False, "error": "Name too short"}
    db_run(
        f"INSERT INTO siem_saved_searches (analyst_id, name, query_json, created_at) "
        f"VALUES ({ph}, {ph}, {ph}, datetime('now'))",
        (analyst_id, name, query_json or "{}"),
    )
    row = db_fetchone("SELECT id FROM siem_saved_searches ORDER BY id DESC LIMIT 1")
    return {"ok": True, "id": int(row["id"]) if row else None}


def delete_saved_search(
    db_run: Callable,
    analyst_id: int,
    search_id: int,
    *,
    ph: str = "?",
) -> dict[str, Any]:
    """Delete owned saved search."""
    db_run(
        f"DELETE FROM siem_saved_searches WHERE id = {ph} AND analyst_id = {ph}",
        (search_id, analyst_id),
    )
    return {"ok": True}


def list_detections(
    db_fetchall: Callable,
    *,
    ph: str = "?",
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Active system findings (notables) with optional rule hint."""
    rows = db_fetchall(
        f"SELECT f.id, f.title, f.severity, f.description, f.resolved, f.created_at, "
        f"f.client_id, f.scan_type "
        f"FROM system_findings f "
        f"WHERE COALESCE(f.resolved, 0) = 0 "
        f"ORDER BY CASE f.severity "
        f"WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, "
        f"f.id DESC LIMIT {int(limit)}",
        (),
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        item["kind"] = "finding"
        item["status"] = "open" if not int(r.get("resolved") or 0) else "resolved"
        out.append(item)
    return out


def group_events(
    db_fetchall: Callable,
    *,
    group_by: str = "event_type",
    hours: int = 24,
    ph: str = "?",
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Aggregate SIEM events by field for Log Activity grouped view."""
    col = "event_type"
    if group_by == "src_ip":
        col = "src_ip"
    elif group_by == "source":
        col = "source"
    rows = db_fetchall(
        f"SELECT {col} AS grp, COUNT(*) AS cnt, MAX(severity) AS max_sev "
        f"FROM siem_events "
        f"WHERE dismissed = 0 AND created_at >= datetime('now', {ph}) "
        f"AND {col} IS NOT NULL AND TRIM({col}) != '' "
        f"GROUP BY {col} ORDER BY cnt DESC LIMIT {int(limit)}",
        (f"-{int(hours)} hours",),
    )
    return [{"group": r["grp"] or "—", "count": int(r["cnt"]), "max_severity": r["max_sev"]} for r in rows]
