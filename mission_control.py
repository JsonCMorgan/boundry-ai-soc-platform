"""
Mission Control queue — Splunk ES-style unified triage (findings, tickets, SOAR).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable


def _age_minutes(created_at: str | None) -> int:
    if not created_at:
        return 0
    try:
        ts = created_at.replace("Z", "+00:00")[:19]
        dt = datetime.fromisoformat(ts)
        return max(0, int((datetime.utcnow() - dt).total_seconds() // 60))
    except (ValueError, TypeError):
        return 0


def mission_control_queue(
    db_fetchall: Callable,
    analyst_id: int,
    *,
    view: str = "all",
    ph: str = "?",
    limit: int = 80,
) -> list[dict[str, Any]]:
    """
    Merge findings, open soc_cases, and open soar_incidents into one queue.

    view: all | new | in_progress | unassigned
    """
    items: list[dict[str, Any]] = []

    findings = db_fetchall(
        f"SELECT id, title, severity, created_at, client_id, scan_type "
        f"FROM system_findings WHERE COALESCE(resolved, 0) = 0 "
        f"ORDER BY id DESC LIMIT 40",
        (),
    )
    for f in findings:
        items.append(
            {
                "queue_type": "finding",
                "id": f["id"],
                "title": f.get("title") or f"Finding #{f['id']}",
                "severity": (f.get("severity") or "MEDIUM").upper(),
                "status": "new",
                "owner": "",
                "client_tag": f.get("client_id") or "boundry_self",
                "created_at": f.get("created_at"),
                "age_min": _age_minutes(f.get("created_at")),
                "href": f"/scan/findings#f{f['id']}",
            }
        )

    cases = db_fetchall(
        f"SELECT id, ticket_no, title, status, priority, severity, client_tag, created_at "
        f"FROM soc_cases WHERE analyst_id = {ph} AND status NOT IN ('closed') "
        f"ORDER BY id DESC LIMIT 40",
        (analyst_id,),
    )
    for c in cases:
        st = (c.get("status") or "new").lower()
        items.append(
            {
                "queue_type": "case",
                "id": c["id"],
                "title": c.get("title") or c.get("ticket_no") or f"Case #{c['id']}",
                "severity": (c.get("severity") or "MEDIUM").upper(),
                "status": st,
                "owner": "self",
                "client_tag": c.get("client_tag") or "",
                "created_at": c.get("created_at"),
                "age_min": _age_minutes(c.get("created_at")),
                "ticket_no": c.get("ticket_no"),
                "href": f"/soc?case={c['id']}",
            }
        )

    incidents = db_fetchall(
        f"SELECT id, title, severity, status, created_at FROM soar_incidents "
        f"WHERE status NOT IN ('closed', 'rejected') ORDER BY id DESC LIMIT 40",
        (),
    )
    for inc in incidents:
        st = (inc.get("status") or "open").lower()
        items.append(
            {
                "queue_type": "soar",
                "id": inc["id"],
                "title": inc.get("title") or f"SOAR #{inc['id']}",
                "severity": (inc.get("severity") or "HIGH").upper(),
                "status": st,
                "owner": "",
                "client_tag": "boundry_self",
                "created_at": inc.get("created_at"),
                "age_min": _age_minutes(inc.get("created_at")),
                "href": f"/soar?id={inc['id']}",
            }
        )

    if view == "new":
        items = [i for i in items if i.get("status") in ("new", "open")]
    elif view == "in_progress":
        items = [i for i in items if i.get("status") in ("working", "in_progress", "open")]
    elif view == "unassigned":
        items = [i for i in items if not (i.get("owner") or "").strip()]

    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    items.sort(key=lambda x: (sev_rank.get(x.get("severity", "INFO"), 9), x.get("age_min", 0)))
    return items[: int(limit)]


def secops_summary(
    db_fetchone: Callable,
    db_fetchall: Callable,
    analyst_id: int,
    *,
    ph: str = "?",
) -> dict[str, Any]:
    """Control Room KPI strip data."""
    open_cases = db_fetchone(
        f"SELECT COUNT(*) AS n FROM soc_cases WHERE analyst_id = {ph} AND status NOT IN ('closed')",
        (analyst_id,),
    )
    closed_7d = db_fetchone(
        f"SELECT COUNT(*) AS n FROM soc_cases WHERE analyst_id = {ph} AND status = 'closed' "
        f"AND created_at >= datetime('now', '-7 days')",
        (analyst_id,),
    )
    open_findings = db_fetchone(
        "SELECT COUNT(*) AS n FROM system_findings WHERE COALESCE(resolved, 0) = 0",
        (),
    )
    soar_open = db_fetchone(
        "SELECT COUNT(*) AS n FROM soar_incidents WHERE status NOT IN ('closed', 'rejected')",
        (),
    )
    pending = db_fetchone(
        "SELECT COUNT(*) AS n FROM soar_actions WHERE status = 'pending'",
        (),
    )
    dismissed_today = db_fetchone(
        "SELECT COUNT(*) AS n FROM siem_events WHERE dismissed = 1 AND date(created_at) = date('now')",
        (),
    )
    queue = mission_control_queue(db_fetchall, analyst_id, view="all", ph=ph, limit=5)
    ages = [i.get("age_min") or 0 for i in mission_control_queue(db_fetchall, analyst_id, ph=ph, limit=50)]
    mean_age = int(sum(ages) / len(ages)) if ages else 0
    return {
        "open_cases": int((open_cases or {}).get("n") or 0),
        "cases_closed_7d": int((closed_7d or {}).get("n") or 0),
        "open_findings": int((open_findings or {}).get("n") or 0),
        "soar_open": int((soar_open or {}).get("n") or 0),
        "soar_pending_approvals": int((pending or {}).get("n") or 0),
        "siem_dismissed_today": int((dismissed_today or {}).get("n") or 0),
        "mean_queue_age_min": mean_age,
        "attention": queue,
    }
