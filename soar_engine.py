"""
Boundry.AI — In-app SOAR engine (Security Orchestration, Automation and Response).

Lightweight playbook runner on top of system_findings + SIEM correlation.
Privacy-first: enrichment uses local Ollama when available; no silent cloud calls.
Destructive / outbound actions require analyst approval.

Usage (from app.py):
    import soar_engine
    soar_engine.start(
        db_run_fn=db_run,
        db_fetchall_fn=db_fetchall,
        db_fetchone_fn=db_fetchone,
        db_insert_fn=db_insert,
        ph=PH,
        set_setting_fn=_set_app_setting,
        get_setting_fn=_get_app_setting,
    )

    # After a new HIGH/CRITICAL finding:
    soar_engine.open_incident_for_finding(finding_db_id, event_type="logon_failed")
"""

from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable, Optional

import playbook_loader

# ── Injected DB helpers ──────────────────────────────────────────────────────
_db_run: Optional[Callable] = None
_db_fetchall: Optional[Callable] = None
_db_fetchone: Optional[Callable] = None
_db_insert: Optional[Callable] = None
_PH = "?"
_set_setting: Optional[Callable] = None
_get_setting: Optional[Callable] = None

# Severities that auto-open a SOAR incident
_AUTO_OPEN_SEVERITIES = {"CRITICAL", "HIGH"}

# Map SIEM event types → preferred playbook id (fallback if MITRE miss)
_EVENT_PLAYBOOK = {
    "logon_failed": "account_compromise",
    "account_locked_out": "account_compromise",
    "explicit_cred_logon": "account_compromise",
    "special_privilege_logon": "account_compromise",
    "login_rate_limited": "account_compromise",
    "shadow_copy_deleted": "ransomware",
    "backup_deleted": "ransomware",
    "mass_file_rename": "ransomware",
    "ransomware_note": "ransomware",
    "defender_disabled": "ransomware",
    "powershell_exec": "ransomware",
    "api_unauthorized": "data_breach",
}

# MITRE technique id from siem_collector._EVENT_MITRE (duplicated lightly for independence)
_EVENT_MITRE = {
    "logon_failed": "T1110",
    "account_locked_out": "T1110",
    "explicit_cred_logon": "T1078",
    "special_privilege_logon": "T1078",
    "login_rate_limited": "T1110",
    "firewall_block": "T1046",
    "audit_log_cleared": "T1070.001",
    "shadow_copy_deleted": "T1490",
    "backup_deleted": "T1490",
    "mass_file_rename": "T1486",
    "ransomware_note": "T1486",
    "defender_disabled": "T1562.001",
    "powershell_exec": "T1059.001",
}


def start(
    db_run_fn: Callable,
    db_fetchall_fn: Callable,
    db_fetchone_fn: Callable,
    db_insert_fn: Callable,
    ph: str = "?",
    set_setting_fn: Optional[Callable] = None,
    get_setting_fn: Optional[Callable] = None,
) -> None:
    """Wire DB helpers. Safe to call once at Flask startup."""
    global _db_run, _db_fetchall, _db_fetchone, _db_insert, _PH
    global _set_setting, _get_setting
    _db_run = db_run_fn
    _db_fetchall = db_fetchall_fn
    _db_fetchone = db_fetchone_fn
    _db_insert = db_insert_fn
    _PH = ph
    _set_setting = set_setting_fn
    _get_setting = get_setting_fn
    print("[soar] Engine started (in-app SOAR ready)")


def _enabled() -> bool:
    """SOAR can be disabled via app_settings key soar_enabled=0."""
    if not _get_setting:
        return True
    val = _get_setting("soar_enabled", "1")
    return str(val) not in ("0", "false", "False", "off")


def open_incident_for_finding(
    finding_db_id: int,
    event_type: str = "",
    group_value: str = "",
    mitre_id: str = "",
    force: bool = False,
) -> Optional[int]:
    """
    Create (or return) an open SOAR incident for a system_findings row.
    Spawns action proposals in a daemon thread so SIEM ingest stays fast.
    Returns soar_incidents.id or None.

    force=True opens even for MEDIUM/LOW (manual analyst trigger).
    """
    if not _db_fetchone or not _enabled():
        return None

    finding = _db_fetchone(
        f"SELECT * FROM system_findings WHERE id = {_PH}",
        (finding_db_id,),
    )
    if not finding:
        return None

    sev = (finding.get("severity") or "MEDIUM").upper()
    if sev not in _AUTO_OPEN_SEVERITIES and not force:
        return None

    existing = _db_fetchone(
        f"SELECT id FROM soar_incidents "
        f"WHERE finding_id = {_PH} AND status NOT IN ('closed','rejected')",
        (finding_db_id,),
    )
    if existing:
        return existing["id"]

    etype = event_type or _guess_event_type(finding)
    mid = mitre_id or _EVENT_MITRE.get(etype, "")
    playbook_id = _match_playbook(mid, etype)
    playbook_title = ""
    if playbook_id:
        pb = playbook_loader.get_playbook(playbook_id)
        playbook_title = (pb or {}).get("title", playbook_id)

    title = finding.get("title") or f"SOAR incident #{finding_db_id}"
    summary = (finding.get("description") or "")[:1500]
    triage = (finding.get("ai_triage") or "")[:2000]

    incident_id = _db_insert(
        f"INSERT INTO soar_incidents "
        f"(finding_id, title, severity, status, playbook_id, playbook_title, "
        f" event_type, mitre_id, group_value, summary, ai_triage_snapshot) "
        f"VALUES ({_PH},{_PH},{_PH},'open',{_PH},{_PH},{_PH},{_PH},{_PH},{_PH},{_PH})",
        (
            finding_db_id, title, sev, playbook_id or "", playbook_title,
            etype, mid, group_value or "", summary, triage,
        ),
        returning="id",
    )
    if not incident_id:
        # Fallback for DBs without returning support
        row = _db_fetchone(
            f"SELECT id FROM soar_incidents WHERE finding_id = {_PH} "
            f"ORDER BY id DESC LIMIT 1",
            (finding_db_id,),
        )
        incident_id = row["id"] if row else None
    if not incident_id:
        return None

    print(f"[soar] Opened incident #{incident_id} for finding #{finding_db_id} "
          f"playbook={playbook_id or 'none'} sev={sev}")

    threading.Thread(
        target=_propose_actions,
        args=(incident_id, finding, etype, group_value, playbook_id),
        daemon=True,
        name=f"soar-propose-{incident_id}",
    ).start()
    return incident_id


def _guess_event_type(finding: dict) -> str:
    """Best-effort event_type from finding title/description."""
    blob = f"{finding.get('title','')} {finding.get('description','')}".lower()
    for key in _EVENT_PLAYBOOK:
        if key.replace("_", " ") in blob or key in blob:
            return key
    if "brute" in blob or "logon" in blob or "login" in blob:
        return "logon_failed"
    if "ransom" in blob:
        return "ransomware_note"
    return ""


def _match_playbook(mitre_id: str, event_type: str) -> str:
    """Prefer MITRE-matched playbook, else event-type map, else empty."""
    if mitre_id:
        matches = playbook_loader.get_playbook_for_finding(mitre_id)
        if matches:
            return matches[0]["id"]
    return _EVENT_PLAYBOOK.get(event_type, "")


def _propose_actions(
    incident_id: int,
    finding: dict,
    event_type: str,
    group_value: str,
    playbook_id: str,
) -> None:
    """Create action rows; auto-execute safe ones immediately."""
    try:
        actions: list[dict[str, Any]] = []

        # Always: analyst daily-log breadcrumb (auto)
        actions.append({
            "action_type": "daily_log_note",
            "label": "Log SOAR open to Daily Log",
            "requires_approval": 0,
            "params": {
                "category": "built",
                "note": (
                    f"[SOAR] Opened incident for finding #{finding.get('id')}: "
                    f"{finding.get('title','')} (sev={finding.get('severity')}, "
                    f"playbook={playbook_id or 'none'})"
                ),
            },
        })

        # Always: attach playbook phase-1 checklist as reference (auto, no side effect)
        if playbook_id:
            pb = playbook_loader.get_playbook(playbook_id) or {}
            phases = pb.get("phases") or []
            phase1 = phases[0] if phases else {}
            steps = []
            for s in (phase1.get("steps") or [])[:8]:
                if isinstance(s, str):
                    steps.append(s)
                elif isinstance(s, dict):
                    steps.append(s.get("text") or s.get("step") or str(s))
                else:
                    steps.append(str(s))
            actions.append({
                "action_type": "attach_playbook",
                "label": f"Attach playbook: {pb.get('title', playbook_id)}",
                "requires_approval": 0,
                "params": {
                    "playbook_id": playbook_id,
                    "phase": phase1.get("label") or phase1.get("phase") or "1",
                    "steps": steps,
                    "do_not": (pb.get("do_not") or [])[:6],
                },
            })

        # Brute-force / credential attacks → propose login lockdown (auto on CRITICAL)
        if event_type in ("logon_failed", "account_locked_out", "login_rate_limited") or \
           "brute" in (finding.get("title") or "").lower():
            sev = (finding.get("severity") or "").upper()
            actions.append({
                "action_type": "login_rate_lockdown",
                "label": "Raise login rate limit to LOCKDOWN (3/min)",
                "requires_approval": 0 if sev == "CRITICAL" else 1,
                "params": {"preset": "lockdown", "previous": None},
            })

        # If we have a group value that looks like an IP → propose suppress (approve)
        ip = group_value or ""
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            actions.append({
                "action_type": "suppress_src_ip",
                "label": f"Suppress further SIEM alerts from {ip}",
                "requires_approval": 1,
                "params": {"src_ip": ip, "reason": "SOAR analyst-approved FP/noise"},
            })
            actions.append({
                "action_type": "draft_block_note",
                "label": f"Draft firewall block recommendation for {ip}",
                "requires_approval": 0,
                "params": {
                    "src_ip": ip,
                    "note": (
                        f"Recommended: block {ip} at the edge firewall / NordVPN "
                        f"split-tunnel review. Do NOT auto-block from Boundry — "
                        f"confirm this IP is not a legitimate remote worker first."
                    ),
                },
            })

        # Propose resolve finding (approve) — never auto-close
        actions.append({
            "action_type": "resolve_finding",
            "label": "Mark finding resolved (after containment)",
            "requires_approval": 1,
            "params": {
                "finding_id": finding.get("id"),
                "resolution_reason": "resolved",
                "resolution_notes": "Closed via SOAR after analyst approval.",
            },
        })

        # Draft client-facing status blurb (auto generate text, no send)
        actions.append({
            "action_type": "draft_status_update",
            "label": "Draft client status update (local only — not emailed)",
            "requires_approval": 0,
            "params": {
                "draft": _client_draft(finding, playbook_id),
            },
        })

        for a in actions:
            _create_and_maybe_run(incident_id, a)

        _db_run(
            f"UPDATE soar_incidents SET status = 'investigating' WHERE id = {_PH} AND status = 'open'",
            (incident_id,),
        )
    except Exception as exc:
        print(f"[soar] _propose_actions error incident={incident_id}: {exc}")


def _client_draft(finding: dict, playbook_id: str) -> str:
    """Local template draft — no LLM required for MVP speed/reliability."""
    return (
        f"We detected a {finding.get('severity', 'HIGH')} security signal: "
        f"{finding.get('title', 'security event')}. Our SOAR playbook "
        f"({playbook_id or 'general IR'}) is in progress. No customer action is "
        f"required unless we contact you with specific steps. We will follow up "
        f"when containment is confirmed."
    )


def _create_and_maybe_run(incident_id: int, action: dict) -> None:
    """Insert action row; execute immediately if approval not required."""
    params_json = json.dumps(action.get("params") or {})
    requires = 1 if action.get("requires_approval") else 0
    status = "pending" if requires else "approved"
    aid = _db_insert(
        f"INSERT INTO soar_actions "
        f"(incident_id, action_type, label, requires_approval, status, params_json) "
        f"VALUES ({_PH},{_PH},{_PH},{_PH},{_PH},{_PH})",
        (
            incident_id,
            action["action_type"],
            action.get("label") or action["action_type"],
            requires,
            status,
            params_json,
        ),
        returning="id",
    )
    if not aid:
        row = _db_fetchone(
            f"SELECT id FROM soar_actions WHERE incident_id = {_PH} "
            f"ORDER BY id DESC LIMIT 1",
            (incident_id,),
        )
        aid = row["id"] if row else None
    if aid and not requires:
        execute_action(aid, executed_by="soar_auto")


def execute_action(action_id: int, executed_by: str = "") -> dict:
    """Run one soar_actions row. Returns {ok, result}."""
    if not _db_fetchone:
        return {"ok": False, "result": "SOAR not started"}

    action = _db_fetchone(f"SELECT * FROM soar_actions WHERE id = {_PH}", (action_id,))
    if not action:
        return {"ok": False, "result": "Action not found"}
    if action["status"] in ("executed", "rejected", "failed"):
        return {"ok": False, "result": f"Action already {action['status']}"}
    if action["requires_approval"] and action["status"] != "approved":
        return {"ok": False, "result": "Action still requires approval"}

    try:
        params = json.loads(action.get("params_json") or "{}")
    except Exception:
        params = {}

    try:
        from datetime import datetime
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        result = _dispatch(action["action_type"], params, action)
        _db_run(
            f"UPDATE soar_actions SET status='executed', executed_at={_PH}, "
            f"executed_by={_PH}, result_text={_PH} WHERE id = {_PH}",
            (now, executed_by or "analyst", (result or "")[:4000], action_id),
        )
        return {"ok": True, "result": result}
    except Exception as exc:
        err = str(exc)[:2000]
        try:
            from datetime import datetime
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            _db_run(
                f"UPDATE soar_actions SET status='failed', executed_at={_PH}, "
                f"executed_by={_PH}, result_text={_PH} WHERE id = {_PH}",
                (now, executed_by or "soar", err, action_id),
            )
        except Exception:
            pass
        return {"ok": False, "result": err}


def _dispatch(action_type: str, params: dict, action: dict) -> str:
    """Execute a single action type. Raises on hard failure."""
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    if action_type == "daily_log_note":
        note = params.get("note") or "SOAR note"
        cat = params.get("category") or "built"
        _db_run(
            f"INSERT INTO daily_log (category, note, sent) VALUES ({_PH},{_PH},0)",
            (cat, note),
        )
        return "Daily log entry created"

    if action_type == "attach_playbook":
        steps = params.get("steps") or []
        text = f"Playbook {params.get('playbook_id')} phase {params.get('phase')}:\n"
        text += "\n".join(f"  • {s}" for s in steps[:8])
        if params.get("do_not"):
            text += "\nDO NOT:\n" + "\n".join(f"  ✗ {d}" for d in params["do_not"][:6])
        return text

    if action_type == "login_rate_lockdown":
        if not _set_setting:
            raise RuntimeError("set_setting not wired")
        prev = _get_setting("login_rate_preset", "normal") if _get_setting else "normal"
        _set_setting("login_rate_preset", "lockdown")
        # Persist previous for undo visibility
        try:
            _db_run(
                f"UPDATE soar_actions SET params_json = {_PH} WHERE id = {_PH}",
                (json.dumps({**params, "previous": prev}), action["id"]),
            )
        except Exception:
            pass
        return f"Login rate preset: {prev} → lockdown (3 per minute)"

    if action_type == "suppress_src_ip":
        ip = params.get("src_ip") or ""
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            raise ValueError(f"Invalid IP: {ip}")
        reason = params.get("reason") or "SOAR suppress"
        existing = _db_fetchone(
            f"SELECT id FROM siem_suppression WHERE suppress_type='ip' AND value={_PH}",
            (ip,),
        )
        if not existing:
            _db_run(
                f"INSERT INTO siem_suppression (suppress_type, value, reason, added_by) "
                f"VALUES ('ip',{_PH},{_PH},'soar')",
                (ip, reason),
            )
            _db_run(
                f"UPDATE siem_events SET dismissed=1 WHERE src_ip={_PH} AND dismissed=0",
                (ip,),
            )
            return f"Suppressed IP {ip} and dismissed matching SIEM events"
        return f"IP {ip} was already on the suppression list"

    if action_type == "draft_block_note":
        return params.get("note") or "No draft"

    if action_type == "draft_status_update":
        return params.get("draft") or "No draft"

    if action_type == "resolve_finding":
        fid = params.get("finding_id")
        if not fid:
            raise ValueError("missing finding_id")
        reason = params.get("resolution_reason") or "resolved"
        notes = params.get("resolution_notes") or "Resolved via SOAR"
        _db_run(
            f"UPDATE system_findings SET resolved=1, resolved_at={_PH}, "
            f"resolution_reason={_PH}, resolution_notes={_PH}, resolved_by={_PH} "
            f"WHERE id = {_PH} AND resolved = 0",
            (now, reason, notes, "soar", fid),
        )
        _db_run(
            f"UPDATE soar_incidents SET status='closed', resolved_at={_PH} "
            f"WHERE finding_id = {_PH} AND status != 'closed'",
            (now, fid),
        )
        return f"Finding #{fid} marked resolved ({reason})"

    raise ValueError(f"Unknown action_type: {action_type}")


def approve_action(action_id: int, analyst_username: str) -> dict:
    """Mark pending action approved and execute it."""
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    action = _db_fetchone(f"SELECT * FROM soar_actions WHERE id = {_PH}", (action_id,))
    if not action:
        return {"ok": False, "error": "Action not found"}
    if action["status"] != "pending":
        return {"ok": False, "error": f"Cannot approve status={action['status']}"}
    _db_run(
        f"UPDATE soar_actions SET status='approved', approved_by={_PH}, approved_at={_PH} "
        f"WHERE id = {_PH}",
        (analyst_username, now, action_id),
    )
    return execute_action(action_id, executed_by=analyst_username)


def reject_action(action_id: int, analyst_username: str, reason: str = "") -> dict:
    """Reject a pending action."""
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    action = _db_fetchone(f"SELECT * FROM soar_actions WHERE id = {_PH}", (action_id,))
    if not action:
        return {"ok": False, "error": "Action not found"}
    if action["status"] != "pending":
        return {"ok": False, "error": f"Cannot reject status={action['status']}"}
    note = reason or "Rejected by analyst"
    _db_run(
        f"UPDATE soar_actions SET status='rejected', approved_by={_PH}, approved_at={_PH}, "
        f"result_text={_PH} WHERE id = {_PH}",
        (analyst_username, now, note, action_id),
    )
    return {"ok": True, "result": note}


def close_incident(incident_id: int, analyst_username: str) -> dict:
    """Manually close a SOAR incident without resolving the finding."""
    from datetime import datetime
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    _db_run(
        f"UPDATE soar_incidents SET status='closed', resolved_at={_PH}, "
        f"assigned_to={_PH} WHERE id = {_PH}",
        (now, analyst_username, incident_id),
    )
    return {"ok": True}


def list_incidents(limit: int = 40, status: str = "") -> list[dict]:
    """Recent SOAR incidents, newest first."""
    if status:
        return _db_fetchall(
            f"SELECT * FROM soar_incidents WHERE status = {_PH} "
            f"ORDER BY id DESC LIMIT {int(limit)}",
            (status,),
        ) or []
    return _db_fetchall(
        f"SELECT * FROM soar_incidents ORDER BY id DESC LIMIT {int(limit)}"
    ) or []


def get_incident(incident_id: int) -> Optional[dict]:
    """Incident + actions bundle."""
    inc = _db_fetchone(f"SELECT * FROM soar_incidents WHERE id = {_PH}", (incident_id,))
    if not inc:
        return None
    actions = _db_fetchall(
        f"SELECT * FROM soar_actions WHERE incident_id = {_PH} ORDER BY id ASC",
        (incident_id,),
    ) or []
    out = dict(inc)
    out["actions"] = actions
    pending = sum(1 for a in actions if a.get("status") == "pending")
    out["pending_count"] = pending
    return out


def stats() -> dict:
    """Dashboard counters."""
    open_n = _db_fetchone(
        f"SELECT COUNT(*) AS c FROM soar_incidents WHERE status NOT IN ('closed','rejected')"
    )
    pending = _db_fetchone(
        f"SELECT COUNT(*) AS c FROM soar_actions WHERE status = 'pending'"
    )
    today = _db_fetchone(
        f"SELECT COUNT(*) AS c FROM soar_incidents WHERE created_at LIKE {_PH}",
        (datetime_prefix_today(),),
    )
    return {
        "open": (open_n or {}).get("c", 0),
        "pending_approvals": (pending or {}).get("c", 0),
        "opened_today": (today or {}).get("c", 0),
    }


def datetime_prefix_today() -> str:
    from datetime import datetime
    return datetime.utcnow().strftime("%Y-%m-%d") + "%"
