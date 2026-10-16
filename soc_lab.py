"""
Live SOC Floor — hybrid real + practice alert queue for Tier-1 laps.

Real lane: open system_findings + HIGH/CRITICAL siem_events.
Practice lane: synthetic MSSP tickets (Career Shift bank patterns), clearly labeled.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from typing import Any, Callable

import career_lab
import intel_lab

# Severity sort weight (higher = more urgent in queue)
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

DISPOSITIONS = [
    {"id": "true_positive", "label": "True positive — contain / escalate"},
    {"id": "false_positive", "label": "False positive / expected activity"},
    {"id": "escalate", "label": "Escalate to Tier-2 / IR"},
    {"id": "monitor", "label": "Monitor — leave open with next action"},
]

# Boundry Tickets ITSM-lite statuses
TICKET_STATUSES = ("new", "working", "waiting", "escalated", "closed")
OPEN_STATUSES = ("new", "working", "waiting", "escalated")
_PRIORITY_FROM_SEV = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
}
# SLA minutes by priority (1 = fastest)
_SLA_MINUTES = {1: 15, 2: 30, 3: 60, 4: 240, 5: 480}
_TRANSITIONS: dict[str, set[str]] = {
    "new": {"working", "closed"},
    "working": {"waiting", "escalated", "closed"},
    "waiting": {"working", "closed"},
    "escalated": {"working", "closed"},
    "closed": set(),
}

CAREER_BRIDGES = [
    {"id": "email", "label": "Email Triage Lab", "href": "/career/email", "why": "Phish / header skills (no Live mailbox yet)"},
    {"id": "edr", "label": "EDR Console Lab", "href": "/career/edr", "why": "Process tree / isolate (no Defender tenant)"},
    {"id": "entra", "label": "Entra CA Lab", "href": "/career/entra", "why": "Identity / Conditional Access storyboards"},
    {"id": "intel", "label": "IOC Enrichment Lab", "href": "/career/intel", "why": "Full enrich drills"},
    {"id": "vuln", "label": "Vuln Queue Lab", "href": "/career/vuln", "why": "CVSS × asset triage practice"},
]


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def _sla_due(minutes: int) -> str:
    return (datetime.utcnow() + timedelta(minutes=max(5, minutes))).strftime("%Y-%m-%d %H:%M:%S")


def build_queue(
    db_fetchall: Callable,
    lane: str = "all",
    ph: str = "?",
) -> list[dict[str, Any]]:
    """Build unified queue items from real + practice sources."""
    lane = (lane or "all").strip().lower()
    items: list[dict[str, Any]] = []

    if lane in ("all", "real"):
        findings = db_fetchall(
            "SELECT id, finding_id, title, severity, category, description, scan_type, created_at "
            "FROM system_findings WHERE resolved = 0 ORDER BY id DESC LIMIT 80"
        ) or []
        for f in findings:
            sev = (f.get("severity") or "MEDIUM").upper()
            items.append({
                "queue_key": f"finding:{f['id']}",
                "source": "finding",
                "source_id": str(f["id"]),
                "is_practice": False,
                "title": f.get("title") or f.get("finding_id") or "Finding",
                "severity": sev,
                "client_tag": "Boundry-Host",
                "detail": (f.get("description") or "")[:400],
                "category": f.get("category") or f.get("scan_type") or "",
                "created_at": f.get("created_at") or "",
                "sla_due_at": None,
                "href_siem": "/siem",
                "href_findings": "/scan/findings",
            })

        events = db_fetchall(
            "SELECT id, source, event_id, event_type, severity, host, user_account, "
            "src_ip, description, created_at FROM siem_events "
            "WHERE dismissed = 0 AND UPPER(severity) IN ('HIGH','CRITICAL') "
            "ORDER BY id DESC LIMIT 80"
        ) or []
        for e in events:
            sev = (e.get("severity") or "HIGH").upper()
            title = e.get("event_type") or e.get("event_id") or "SIEM event"
            items.append({
                "queue_key": f"siem:{e['id']}",
                "source": "siem",
                "source_id": str(e["id"]),
                "is_practice": False,
                "title": str(title).replace("_", " "),
                "severity": sev,
                "client_tag": "Boundry-Host",
                "detail": (e.get("description") or "")[:400],
                "category": e.get("source") or "",
                "host": e.get("host") or "",
                "src_ip": e.get("src_ip") or "",
                "created_at": e.get("created_at") or "",
                "sla_due_at": None,
                "href_siem": "/siem",
                "href_spl": "/siem/query",
            })

    if lane in ("all", "practice"):
        practice = db_fetchall(
            "SELECT id, client_tag, title, severity, detail, source_label, "
            "sla_due_at, created_at, status FROM soc_practice_events "
            "WHERE status = 'open' ORDER BY id DESC LIMIT 80"
        ) or []
        for p in practice:
            sev = (p.get("severity") or "MEDIUM").upper()
            items.append({
                "queue_key": f"practice:{p['id']}",
                "source": "practice",
                "source_id": str(p["id"]),
                "is_practice": True,
                "title": p.get("title") or "Practice alert",
                "severity": sev,
                "client_tag": p.get("client_tag") or "Practice",
                "detail": (p.get("detail") or "")[:400],
                "category": p.get("source_label") or "practice",
                "created_at": p.get("created_at") or "",
                "sla_due_at": p.get("sla_due_at"),
                "href_career_shift": "/career/shift",
            })

    items.sort(
        key=lambda x: (
            _SEV_RANK.get(str(x.get("severity") or "").upper(), 9),
            x.get("sla_due_at") or "9999",
            -(int(str(x.get("source_id") or "0") or 0) if str(x.get("source_id") or "").isdigit() else 0),
        )
    )
    return items


# Extra practice templates for SLA-race variety (G3 / desk-ready)
_PRACTICE_EXTRAS: list[dict[str, Any]] = [
    {
        "title": "SLA race: VIP mailbox forward rule",
        "severity": "HIGH",
        "detail": "NorthPeak CFO mailbox created external forward within 4 minutes of a phishing click.",
        "source": "email",
        "hint": "Contain identity + remove rule before writing the client update.",
        "mitre": "T1114",
        "disposition": "true_positive",
        "client_id": "northpeak",
        "sla_minutes": 8,
    },
    {
        "title": "SLA race: Harbor EDR ransomware note",
        "severity": "CRITICAL",
        "detail": "Harbor warehouse PC shows ransom note file + mass file renames. Isolate decision needed.",
        "source": "edr",
        "hint": "Isolate first; enrich hash second.",
        "mitre": "T1486",
        "disposition": "escalate",
        "client_id": "harbor",
        "sla_minutes": 5,
    },
    {
        "title": "Quiet Contoso spray (weekend FP candidate)",
        "severity": "MEDIUM",
        "detail": "Contoso Entra: 12 failed logons for one service account from known scanner IP.",
        "source": "identity",
        "hint": "Validate scanner allow-list before escalate.",
        "mitre": "T1110",
        "disposition": "false_positive",
        "client_id": "contoso",
        "sla_minutes": 35,
    },
    {
        "title": "Dual-client DNS spike",
        "severity": "HIGH",
        "detail": "Contoso and Harbor both show rare domain lookups to the same newly registered host.",
        "source": "dns",
        "hint": "Enrich IOC once; ticket both clients with shared intel note.",
        "mitre": "T1071",
        "disposition": "true_positive",
        "client_id": "contoso",
        "sla_minutes": 15,
    },
]


def inject_practice_events(
    db_run: Callable,
    count: int = 5,
    ph: str = "?",
    db_fetchall: Callable | None = None,
) -> int:
    """
    Insert synthetic practice alerts with client rotation and SLA mix.

    Prefer unused titles when db_fetchall is provided. Guarantees at least one
    tight SLA (<=12m) and spreads clients across Contoso / NorthPeak / Harbor.
    """
    count = max(1, min(int(count or 5), 12))
    bank = list(getattr(career_lab, "_ALERT_BANK", []) or []) + list(_PRACTICE_EXTRAS)
    if not bank:
        return 0
    clients = {c["id"]: c for c in career_lab.list_mssp_clients()}
    client_ids = [c["id"] for c in career_lab.list_mssp_clients()] or ["contoso"]

    recent_titles: set[str] = set()
    if db_fetchall is not None:
        try:
            rows = db_fetchall(
                f"SELECT title FROM soc_practice_events "
                f"WHERE created_at >= datetime('now', '-2 days') LIMIT 80",
            ) or []
            recent_titles = {str(r.get("title") or "") for r in rows}
        except Exception:
            recent_titles = set()

    fresh = [a for a in bank if (a.get("title") or "") not in recent_titles]
    pool = fresh if len(fresh) >= count else bank
    picks = random.sample(pool, k=min(count, len(pool))) if len(pool) >= count else [
        random.choice(pool) for _ in range(count)
    ]

    # Force client rotation across the batch
    for i, alert in enumerate(picks):
        if not alert.get("client_id") or i < len(client_ids):
            alert = dict(alert)
            alert["client_id"] = client_ids[i % len(client_ids)]
            picks[i] = alert

    # Guarantee one tight SLA race in the batch
    if picks and not any(int(a.get("sla_minutes") or 30) <= 12 for a in picks):
        picks[0] = dict(picks[0])
        picks[0]["sla_minutes"] = random.choice([5, 8, 10, 12])
        picks[0]["severity"] = picks[0].get("severity") or "HIGH"
        title = picks[0].get("title") or "Practice alert"
        if "SLA" not in title:
            picks[0]["title"] = f"SLA race: {title}"

    # Mix one longer SLA so the queue is not all fires
    if len(picks) >= 3 and not any(int(a.get("sla_minutes") or 0) >= 30 for a in picks):
        picks[-1] = dict(picks[-1])
        picks[-1]["sla_minutes"] = random.choice([30, 35, 40, 45])

    n = 0
    for alert in picks:
        cid = alert.get("client_id") or "contoso"
        client = clients.get(cid) or {"name": cid, "tier": "Silver"}
        sla_m = int(alert.get("sla_minutes") or 30)
        db_run(
            f"INSERT INTO soc_practice_events "
            f"(client_tag, client_id, title, severity, detail, source_label, "
            f" hint, mitre, expected_disposition, sla_due_at, status, created_at) "
            f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, "
            f"'open', datetime('now'))",
            (
                f"{client.get('name')} ({client.get('tier')})",
                cid,
                alert.get("title") or "Practice alert",
                (alert.get("severity") or "MEDIUM").upper(),
                alert.get("detail") or "",
                alert.get("source") or "practice",
                alert.get("hint") or "",
                alert.get("mitre") or "",
                alert.get("disposition") or "",
                _sla_due(sla_m),
            ),
        )
        n += 1
    return n


def priority_from_severity(severity: str) -> int:
    """Map alert severity to ticket priority 1–5."""
    return _PRIORITY_FROM_SEV.get((severity or "MEDIUM").upper(), 3)


def mint_ticket_no(db_fetchone: Callable, ph: str = "?") -> str:
    """Allocate next BT-YYYY-NNNN ticket number for the current year."""
    year = datetime.utcnow().strftime("%Y")
    prefix = f"BT-{year}-"
    row = db_fetchone(
        f"SELECT ticket_no FROM soc_cases WHERE ticket_no LIKE {ph} "
        f"ORDER BY ticket_no DESC LIMIT 1",
        (prefix + "%",),
    )
    seq = 1
    if row and row.get("ticket_no"):
        try:
            seq = int(str(row["ticket_no"]).split("-")[-1]) + 1
        except Exception:
            seq = 1
    return f"{prefix}{seq:04d}"


def append_ticket_event(
    db_run: Callable,
    case_id: int,
    *,
    actor_kind: str,
    event_type: str,
    body: str = "",
    ph: str = "?",
) -> None:
    """Append a Boundry Tickets timeline event."""
    kind = (actor_kind or "human").strip().lower()
    if kind not in ("human", "agent_proposed", "system"):
        kind = "human"
    db_run(
        f"INSERT INTO soc_ticket_events (case_id, actor_kind, event_type, body, created_at) "
        f"VALUES ({ph}, {ph}, {ph}, {ph}, datetime('now'))",
        (case_id, kind, (event_type or "")[:80], (body or "")[:4000]),
    )


def get_ticket_timeline(
    db_fetchall: Callable,
    case_id: int,
    ph: str = "?",
) -> list[dict[str, Any]]:
    """Return timeline events oldest-first."""
    rows = db_fetchall(
        f"SELECT id, case_id, actor_kind, event_type, body, created_at "
        f"FROM soc_ticket_events WHERE case_id = {ph} ORDER BY id ASC",
        (case_id,),
    ) or []
    return [
        {
            "id": r.get("id"),
            "actor_kind": r.get("actor_kind") or "human",
            "event_type": r.get("event_type") or "",
            "body": r.get("body") or "",
            "created_at": r.get("created_at") or "",
        }
        for r in rows
    ]


def open_case(
    db_run: Callable,
    db_fetchone: Callable,
    analyst_id: int,
    source: str,
    source_id: str,
    ph: str = "?",
) -> dict[str, Any]:
    """Create or return existing open Boundry Ticket for a queue item."""
    source = (source or "").strip().lower()
    source_id = str(source_id or "").strip()
    if source not in ("finding", "siem", "practice") or not source_id:
        return {"ok": False, "error": "Need source (finding|siem|practice) and source_id"}

    existing = db_fetchone(
        f"SELECT * FROM soc_cases WHERE source = {ph} AND source_id = {ph} "
        f"AND status IN ('new','working','waiting','escalated','open') "
        f"ORDER BY id DESC LIMIT 1",
        (source, source_id),
    )
    if existing:
        # Backfill ticket_no on legacy rows
        if not (existing.get("ticket_no") or "").strip():
            tno = mint_ticket_no(db_fetchone, ph=ph)
            db_run(
                f"UPDATE soc_cases SET ticket_no = {ph} WHERE id = {ph}",
                (tno, existing["id"]),
            )
            existing = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (existing["id"],))
        return {"ok": True, "case": _public_case(existing), "created": False}

    meta = _resolve_source_meta(db_fetchone, source, source_id, ph=ph)
    if not meta:
        return {"ok": False, "error": "Queue item not found or already closed"}

    shift = db_fetchone(
        f"SELECT id FROM soc_shift_sessions WHERE analyst_id = {ph} AND ended_at IS NULL "
        f"ORDER BY id DESC LIMIT 1",
        (analyst_id,),
    )
    shift_id = (shift or {}).get("id")
    sev = meta["severity"]
    priority = priority_from_severity(sev)
    sla = meta.get("sla_due_at") or _sla_due(_SLA_MINUTES.get(priority, 60))
    ticket_no = mint_ticket_no(db_fetchone, ph=ph)

    db_run(
        f"INSERT INTO soc_cases "
        f"(source, source_id, client_tag, severity, status, title, detail, "
        f" summary, next_action, enrich_notes, disposition, sla_due_at, "
        f" analyst_id, shift_id, ticket_no, priority, created_at) "
        f"VALUES ({ph}, {ph}, {ph}, {ph}, 'new', {ph}, {ph}, '', '', '', '', "
        f"{ph}, {ph}, {ph}, {ph}, {ph}, datetime('now'))",
        (
            source,
            source_id,
            meta["client_tag"],
            sev,
            meta["title"],
            meta["detail"],
            sla,
            analyst_id,
            shift_id,
            ticket_no,
            priority,
        ),
    )
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE source = {ph} AND source_id = {ph} "
        f"AND analyst_id = {ph} ORDER BY id DESC LIMIT 1",
        (source, source_id, analyst_id),
    )
    if row:
        append_ticket_event(
            db_run, int(row["id"]),
            actor_kind="system",
            event_type="opened",
            body=f"Ticket {ticket_no} opened from {source}.",
            ph=ph,
        )
    return {"ok": True, "case": _public_case(row), "created": True}


def _resolve_source_meta(
    db_fetchone: Callable,
    source: str,
    source_id: str,
    ph: str = "?",
) -> dict[str, Any] | None:
    """Load title/detail/severity/client for a queue source."""
    if source == "finding":
        f = db_fetchone(
            f"SELECT id, title, severity, description FROM system_findings "
            f"WHERE id = {ph} AND resolved = 0",
            (int(source_id),),
        )
        if not f:
            return None
        return {
            "title": f.get("title") or "Finding",
            "detail": f.get("description") or "",
            "severity": (f.get("severity") or "MEDIUM").upper(),
            "client_tag": "Boundry-Host",
            "sla_due_at": None,
        }
    if source == "siem":
        e = db_fetchone(
            f"SELECT id, event_type, event_id, severity, description FROM siem_events "
            f"WHERE id = {ph} AND dismissed = 0",
            (int(source_id),),
        )
        if not e:
            return None
        return {
            "title": (e.get("event_type") or e.get("event_id") or "SIEM event").replace("_", " "),
            "detail": e.get("description") or "",
            "severity": (e.get("severity") or "HIGH").upper(),
            "client_tag": "Boundry-Host",
            "sla_due_at": None,
        }
    if source == "practice":
        p = db_fetchone(
            f"SELECT * FROM soc_practice_events WHERE id = {ph} AND status = 'open'",
            (int(source_id),),
        )
        if not p:
            return None
        return {
            "title": p.get("title") or "Practice alert",
            "detail": p.get("detail") or "",
            "severity": (p.get("severity") or "MEDIUM").upper(),
            "client_tag": p.get("client_tag") or "Practice",
            "sla_due_at": p.get("sla_due_at"),
        }
    return None


def _public_case(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    status = row.get("status") or "new"
    if status == "open":
        status = "new"
    return {
        "id": row.get("id"),
        "ticket_no": row.get("ticket_no") or "",
        "source": row.get("source"),
        "source_id": row.get("source_id"),
        "is_practice": row.get("source") == "practice",
        "client_tag": row.get("client_tag") or "",
        "severity": row.get("severity") or "",
        "priority": int(row.get("priority") or priority_from_severity(row.get("severity") or "")),
        "status": status,
        "title": row.get("title") or "",
        "detail": row.get("detail") or "",
        "summary": row.get("summary") or "",
        "next_action": row.get("next_action") or "",
        "enrich_notes": row.get("enrich_notes") or "",
        "disposition": row.get("disposition") or "",
        "sla_due_at": row.get("sla_due_at"),
        "escalate_note": row.get("escalate_note") or "",
        "escalated_at": row.get("escalated_at"),
        "created_at": row.get("created_at") or "",
        "updated_at": row.get("updated_at") or row.get("created_at") or "",
        "closed_at": row.get("closed_at"),
        "soar_incident_id": row.get("soar_incident_id"),
        "allowed_transitions": sorted(_TRANSITIONS.get(status, set())),
    }


def update_case(
    db_run: Callable,
    db_fetchone: Callable,
    case_id: int,
    analyst_id: int,
    fields: dict[str, Any],
    ph: str = "?",
) -> dict[str, Any]:
    """Update hygiene fields on an open ticket (does not change status machine)."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    if row.get("status") in ("closed",):
        return {"ok": False, "error": "Ticket already closed"}

    summary = fields.get("summary", row.get("summary") or "")
    next_action = fields.get("next_action", row.get("next_action") or "")
    enrich_notes = fields.get("enrich_notes", row.get("enrich_notes") or "")
    disposition = fields.get("disposition", row.get("disposition") or "")
    priority = row.get("priority") or 3
    sla_due = row.get("sla_due_at")
    if "priority" in fields and fields.get("priority") is not None:
        try:
            priority = max(1, min(5, int(fields["priority"])))
        except Exception:
            priority = 3
        if priority != int(row.get("priority") or 0):
            sla_due = _sla_due(_SLA_MINUTES.get(priority, 60))
            append_ticket_event(
                db_run, case_id,
                actor_kind="human",
                event_type="priority_change",
                body=f"Priority set to P{priority}.",
                ph=ph,
            )

    # Save may auto-move new → working
    status = row.get("status") or "new"
    if status == "open":
        status = "new"
    if status == "new" and (
        (summary or "").strip() or (next_action or "").strip() or (enrich_notes or "").strip()
    ):
        status = "working"
        append_ticket_event(
            db_run, case_id,
            actor_kind="human",
            event_type="transition",
            body="new → working (work started on save).",
            ph=ph,
        )

    db_run(
        f"UPDATE soc_cases SET summary = {ph}, next_action = {ph}, enrich_notes = {ph}, "
        f"disposition = {ph}, status = {ph}, priority = {ph}, sla_due_at = {ph} "
        f"WHERE id = {ph}",
        (summary, next_action, enrich_notes, disposition, status, priority, sla_due, case_id),
    )
    updated = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (case_id,))
    return {"ok": True, "case": _public_case(updated)}


def transition_case(
    db_run: Callable,
    db_fetchone: Callable,
    case_id: int,
    analyst_id: int,
    to_status: str,
    note: str = "",
    *,
    disposition: str | None = None,
    summary: str | None = None,
    next_action: str | None = None,
    ph: str = "?",
) -> dict[str, Any]:
    """Apply a Boundry Tickets state transition with timeline audit."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    cur = row.get("status") or "new"
    if cur == "open":
        cur = "new"
    dest = (to_status or "").strip().lower()
    if dest not in TICKET_STATUSES:
        return {"ok": False, "error": f"Unknown status '{dest}'"}
    if dest not in _TRANSITIONS.get(cur, set()):
        return {"ok": False, "error": f"Cannot move {cur} → {dest}"}

    note = (note or "").strip()
    if dest == "escalated":
        if len(note) < 12:
            return {
                "ok": False,
                "error": "Escalate note required (who / what / why, min ~12 chars).",
            }
        db_run(
            f"UPDATE soc_cases SET status = 'escalated', escalate_note = {ph}, "
            f"escalated_at = datetime('now') WHERE id = {ph}",
            (note, case_id),
        )
        append_ticket_event(
            db_run, case_id,
            actor_kind="human",
            event_type="escalated",
            body=note,
            ph=ph,
        )
        updated = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (case_id,))
        return {"ok": True, "case": _public_case(updated)}

    if dest == "closed":
        return close_case(
            db_run, db_fetchone, case_id, analyst_id,
            disposition=disposition if disposition is not None else (row.get("disposition") or ""),
            summary=summary if summary is not None else (row.get("summary") or ""),
            next_action=next_action if next_action is not None else (row.get("next_action") or ""),
            ph=ph,
        )

    db_run(f"UPDATE soc_cases SET status = {ph} WHERE id = {ph}", (dest, case_id))
    body = f"{cur} → {dest}"
    if note:
        body += f". {note}"
    append_ticket_event(
        db_run, case_id,
        actor_kind="human",
        event_type="transition",
        body=body,
        ph=ph,
    )
    updated = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (case_id,))
    return {"ok": True, "case": _public_case(updated)}


def add_ticket_comment(
    db_run: Callable,
    db_fetchone: Callable,
    db_fetchall: Callable,
    case_id: int,
    analyst_id: int,
    body: str,
    ph: str = "?",
) -> dict[str, Any]:
    """Add a human comment to the ticket timeline."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    text = (body or "").strip()
    if len(text) < 2:
        return {"ok": False, "error": "Comment too short"}
    append_ticket_event(
        db_run, case_id,
        actor_kind="human",
        event_type="comment",
        body=text,
        ph=ph,
    )
    return {
        "ok": True,
        "case": _public_case(row),
        "timeline": get_ticket_timeline(db_fetchall, case_id, ph=ph),
    }


def get_case_bundle(
    db_fetchone: Callable,
    db_fetchall: Callable,
    case_id: int,
    analyst_id: int,
    ph: str = "?",
) -> dict[str, Any]:
    """Ticket + timeline for workspace."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    return {
        "ok": True,
        "case": _public_case(row),
        "timeline": get_ticket_timeline(db_fetchall, case_id, ph=ph),
    }


def link_soar_to_case(
    db_run: Callable,
    db_fetchone: Callable,
    case_id: int,
    analyst_id: int,
    soar_incident_id: int,
    ph: str = "?",
) -> dict[str, Any]:
    """Attach SOAR incident id and log agent_proposed timeline step."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    db_run(
        f"UPDATE soc_cases SET soar_incident_id = {ph} WHERE id = {ph}",
        (soar_incident_id, case_id),
    )
    append_ticket_event(
        db_run, case_id,
        actor_kind="agent_proposed",
        event_type="soar_opened",
        body=f"SOAR incident #{soar_incident_id} opened; actions require human approve.",
        ph=ph,
    )
    updated = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (case_id,))
    return {"ok": True, "case": _public_case(updated)}


def note_soar_human_gate(
    db_run: Callable,
    db_fetchone: Callable,
    soar_incident_id: int,
    *,
    approved: bool,
    actor: str,
    reason: str = "",
    ph: str = "?",
) -> None:
    """If a ticket is linked to this SOAR incident, append human gate event."""
    row = db_fetchone(
        f"SELECT id FROM soc_cases WHERE soar_incident_id = {ph} ORDER BY id DESC LIMIT 1",
        (soar_incident_id,),
    )
    if not row:
        return
    verb = "approved" if approved else "rejected"
    body = f"SOAR action {verb} by {actor or 'analyst'}."
    if reason:
        body += f" Reason: {reason[:500]}"
    append_ticket_event(
        db_run, int(row["id"]),
        actor_kind="human",
        event_type="soar_" + verb,
        body=body,
        ph=ph,
    )


def ops_status_strip(
    db_fetchone: Callable,
    analyst_id: int,
    *,
    ph: str = "?",
    active_shift: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Counts for Live Ops status strip (open BT, SLA overdue, shift)."""
    open_row = db_fetchone(
        f"SELECT COUNT(*) AS c FROM soc_cases WHERE analyst_id = {ph} "
        f"AND status IN ('new','working','waiting','escalated','open')",
        (analyst_id,),
    )
    overdue_row = db_fetchone(
        f"SELECT COUNT(*) AS c FROM soc_cases WHERE analyst_id = {ph} "
        f"AND status IN ('new','working','waiting','escalated','open') "
        f"AND sla_due_at IS NOT NULL AND sla_due_at != '' "
        f"AND sla_due_at < datetime('now')",
        (analyst_id,),
    )
    shift_on = bool(active_shift and active_shift.get("active"))
    return {
        "open_tickets": int((open_row or {}).get("c") or 0),
        "sla_overdue": int((overdue_row or {}).get("c") or 0),
        "shift_active": shift_on,
        "shift_id": (active_shift or {}).get("id") if shift_on else None,
        "honesty": "Practice never equals Real. Lane badges stay on every ticket.",
    }


def list_tickets(
    db_fetchall: Callable,
    analyst_id: int,
    *,
    status: str = "",
    client: str = "",
    q: str = "",
    ph: str = "?",
    limit: int = 80,
) -> list[dict[str, Any]]:
    """List Boundry Tickets for the analyst with optional filters."""
    clauses = [f"analyst_id = {ph}"]
    params: list[Any] = [analyst_id]
    st = (status or "").strip().lower()
    if st == "open":
        clauses.append(
            "status IN ('new','working','waiting','escalated','open')"
        )
    elif st in TICKET_STATUSES:
        if st == "new":
            clauses.append("status IN ('new','open')")
        else:
            clauses.append(f"status = {ph}")
            params.append(st)
    cl = (client or "").strip()
    if cl:
        clauses.append(f"client_tag LIKE {ph}")
        params.append(f"%{cl}%")
    query = (q or "").strip()
    if query:
        clauses.append(
            f"(ticket_no LIKE {ph} OR title LIKE {ph} OR summary LIKE {ph})"
        )
        like = f"%{query}%"
        params.extend([like, like, like])
    sql = (
        "SELECT * FROM soc_cases WHERE "
        + " AND ".join(clauses)
        + " ORDER BY "
        + "CASE status "
        + "WHEN 'escalated' THEN 0 WHEN 'new' THEN 1 WHEN 'open' THEN 1 "
        + "WHEN 'working' THEN 2 WHEN 'waiting' THEN 3 ELSE 4 END, "
        + "priority ASC, id DESC LIMIT "
        + str(max(1, min(200, int(limit))))
    )
    rows = db_fetchall(sql, tuple(params)) or []
    return [_public_case(r) for r in rows if r]


def close_case(
    db_run: Callable,
    db_fetchone: Callable,
    case_id: int,
    analyst_id: int,
    disposition: str,
    summary: str,
    next_action: str,
    ph: str = "?",
) -> dict[str, Any]:
    """Close ticket; close practice event or leave finding/siem for explicit resolve."""
    row = db_fetchone(
        f"SELECT * FROM soc_cases WHERE id = {ph} AND analyst_id = {ph}",
        (case_id, analyst_id),
    )
    if not row:
        return {"ok": False, "error": "Ticket not found"}
    if (row.get("status") or "") == "closed":
        return {"ok": False, "error": "Ticket already closed"}
    disp = (disposition or row.get("disposition") or "").strip()
    if not disp:
        return {"ok": False, "error": "Pick a disposition before close"}
    summ = (summary if summary is not None else row.get("summary")) or ""
    nxt = (next_action if next_action is not None else row.get("next_action")) or ""
    if len(summ.strip()) < 8:
        return {"ok": False, "error": "Write a short case summary (what you saw) before close"}
    if len(nxt.strip()) < 4:
        return {"ok": False, "error": "Write next_action (what happens after close) before close"}

    db_run(
        f"UPDATE soc_cases SET status = 'closed', disposition = {ph}, summary = {ph}, "
        f"next_action = {ph}, closed_at = datetime('now') WHERE id = {ph}",
        (disp, summ, nxt, case_id),
    )
    append_ticket_event(
        db_run, case_id,
        actor_kind="human",
        event_type="closed",
        body=f"Closed as {disp}. Next: {nxt[:200]}",
        ph=ph,
    )
    if row.get("source") == "practice":
        try:
            db_run(
                f"UPDATE soc_practice_events SET status = 'closed', "
                f"closed_at = datetime('now') WHERE id = {ph}",
                (int(row["source_id"]),),
            )
        except Exception:
            pass
    updated = db_fetchone(f"SELECT * FROM soc_cases WHERE id = {ph}", (case_id,))
    return {"ok": True, "case": _public_case(updated)}


def start_shift(
    db_run: Callable,
    db_fetchone: Callable,
    analyst_id: int,
    ph: str = "?",
) -> dict[str, Any]:
    """Start a Live Shift session."""
    active = db_fetchone(
        f"SELECT * FROM soc_shift_sessions WHERE analyst_id = {ph} AND ended_at IS NULL "
        f"ORDER BY id DESC LIMIT 1",
        (analyst_id,),
    )
    if active:
        return {"ok": True, "shift": _public_shift(active), "already_open": True}

    db_run(
        f"INSERT INTO soc_shift_sessions (analyst_id, started_at, stats_json) "
        f"VALUES ({ph}, datetime('now'), '{{}}')",
        (analyst_id,),
    )
    row = db_fetchone(
        f"SELECT * FROM soc_shift_sessions WHERE analyst_id = {ph} AND ended_at IS NULL "
        f"ORDER BY id DESC LIMIT 1",
        (analyst_id,),
    )
    return {"ok": True, "shift": _public_shift(row), "already_open": False}


def grade_handoff(note: str, open_titles: list[str] | None = None) -> dict[str, Any]:
    """
    G14 rubric for end-of-shift handoff notes.

    Scores 0–100 on: what you did, what stays open, next action, client/severity cue.
    """
    text = (note or "").strip()
    low = text.lower()
    open_titles = open_titles or []
    checks = [
        {
            "id": "actions",
            "label": "What you did / closed",
            "ok": any(
                k in low
                for k in (
                    "closed", "resolved", "escalat", "false positive", "fp",
                    "true positive", "tp", "disposed", "cleared", "contained",
                )
            ),
            "tip": "Name at least one action or disposition (closed / escalated / FP).",
        },
        {
            "id": "open_items",
            "label": "What stays open",
            "ok": (
                any(k in low for k in ("open", "still", "watch", "pending", "handoff", "left"))
                or (not open_titles and "none" in low)
            ),
            "tip": "Call out remaining open items, or say none left open.",
        },
        {
            "id": "next",
            "label": "Next action for the next analyst",
            "ok": any(
                k in low
                for k in ("next", "please", "follow", "verify", "check", "confirm", "need to")
            ),
            "tip": "Give the next analyst one concrete next step.",
        },
        {
            "id": "context",
            "label": "Client / severity / case cue",
            "ok": any(
                k in low
                for k in (
                    "client", "contoso", "northpeak", "harbor", "critical", "high",
                    "medium", "low", "sla", "case", "severity",
                )
            ) or any((t or "").lower()[:12] in low for t in open_titles if t),
            "tip": "Tag a client, severity, or case title so the next shift can find it.",
        },
    ]
    passed = sum(1 for c in checks if c["ok"])
    score = round(100 * passed / max(len(checks), 1))
    tips = [c["tip"] for c in checks if not c["ok"]]
    if score >= 75:
        summary = "Solid handoff. Next shift can pick up without guessing."
    elif score >= 50:
        summary = "Usable handoff. Tighten the missing rubric lines below."
    else:
        summary = "Thin handoff. Expand so the next analyst is not blind."
    return {
        "score": score,
        "passed": passed,
        "total": len(checks),
        "checks": checks,
        "tips": tips[:3],
        "summary": summary,
    }


def end_shift(
    db_run: Callable,
    db_fetchone: Callable,
    db_fetchall: Callable,
    analyst_id: int,
    handoff_note: str,
    ph: str = "?",
) -> dict[str, Any]:
    """End active shift with handoff note, stats, and G14 rubric grade."""
    active = db_fetchone(
        f"SELECT * FROM soc_shift_sessions WHERE analyst_id = {ph} AND ended_at IS NULL "
        f"ORDER BY id DESC LIMIT 1",
        (analyst_id,),
    )
    if not active:
        return {"ok": False, "error": "No active Live Shift"}
    note = (handoff_note or "").strip()
    if len(note) < 12:
        return {"ok": False, "error": "Handoff note too short. List open items and what you did."}

    closed = db_fetchall(
        f"SELECT id, source, disposition FROM soc_cases "
        f"WHERE shift_id = {ph} AND status = 'closed'",
        (active["id"],),
    ) or []
    still_open = db_fetchall(
        f"SELECT id, title, severity FROM soc_cases "
        f"WHERE shift_id = {ph} AND status IN "
        f"('new','working','waiting','escalated','open')",
        (active["id"],),
    ) or []
    rubric = grade_handoff(note, [r.get("title") or "" for r in still_open])
    stats = {
        "closed": len(closed),
        "left_open": len(still_open),
        "by_disposition": {},
        "handoff_rubric": rubric,
    }
    for c in closed:
        d = c.get("disposition") or "unknown"
        stats["by_disposition"][d] = stats["by_disposition"].get(d, 0) + 1

    db_run(
        f"UPDATE soc_shift_sessions SET ended_at = datetime('now'), "
        f"handoff_note = {ph}, stats_json = {ph} WHERE id = {ph}",
        (note, json.dumps(stats), active["id"]),
    )
    row = db_fetchone(f"SELECT * FROM soc_shift_sessions WHERE id = {ph}", (active["id"],))
    return {"ok": True, "shift": _public_shift(row), "stats": stats, "handoff_rubric": rubric}


def _public_shift(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if not row:
        return None
    stats = {}
    try:
        stats = json.loads(row.get("stats_json") or "{}")
    except Exception:
        stats = {}
    return {
        "id": row.get("id"),
        "started_at": row.get("started_at"),
        "ended_at": row.get("ended_at"),
        "handoff_note": row.get("handoff_note") or "",
        "stats": stats,
        "active": not row.get("ended_at"),
    }


def get_active_shift(
    db_fetchone: Callable,
    analyst_id: int,
    ph: str = "?",
) -> dict[str, Any] | None:
    """Return active shift or None."""
    row = db_fetchone(
        f"SELECT * FROM soc_shift_sessions WHERE analyst_id = {ph} AND ended_at IS NULL "
        f"ORDER BY id DESC LIMIT 1",
        (analyst_id,),
    )
    return _public_shift(row)


def enrich_ioc(value: str) -> dict[str, Any]:
    """Local IOC enrich stub for case workspace (intel_lab)."""
    return intel_lab.lookup_ioc(value)


def context_for_item(item: dict[str, Any] | None) -> dict[str, Any]:
    """Right-rail context + Career bridges."""
    item = item or {}
    bridges = list(CAREER_BRIDGES)
    title = (item.get("title") or "").lower()
    detail = (item.get("detail") or "").lower()
    blob = title + " " + detail
    suggested = []
    if any(k in blob for k in ("phish", "mail", "bec", "spf", "dkim")):
        suggested.append("email")
    if any(k in blob for k in ("powershell", "process", "malware", "isolate", "endpoint")):
        suggested.append("edr")
    if any(k in blob for k in ("mfa", "entra", "sign-in", "identity", "conditional")):
        suggested.append("entra")
    if any(k in blob for k in ("cve", "vuln", "patch", "cvss")):
        suggested.append("vuln")
    if item.get("src_ip") or any(k in blob for k in ("ip ", "hash", "domain", "ioc")):
        suggested.append("intel")
    return {
        "client_tag": item.get("client_tag") or "",
        "severity": item.get("severity") or "",
        "is_practice": bool(item.get("is_practice")),
        "playbook_href": "/playbooks",
        "siem_href": item.get("href_siem") or "/siem",
        "spl_href": item.get("href_spl") or "/siem/query",
        "findings_href": item.get("href_findings") or "/scan/findings",
        "career_bridges": bridges,
        "suggested_bridge_ids": suggested,
        "banner": (
            "Practice client traffic — not your machine."
            if item.get("is_practice")
            else "Real Boundry host telemetry / findings."
        ),
    }
