"""
One-click false-positive templates for SIEM correlation findings.

Each template performs analyst-approved actions atomically (suppress + resolve).
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Callable

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOC_IP_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")

TEMPLATE_IDS = frozenset(
    {"internet_port_scan", "documentation_test_ip", "expected_vendor_service"}
)


def extract_first_ipv4(text: str) -> str:
    """Return first IPv4 in text or empty string."""
    m = _IP_RE.search(text or "")
    return m.group(1) if m else ""


def _is_documentation_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in _DOC_IP_PREFIXES)


def _ensure_suppression(
    db_fetchone: Callable[..., Any],
    db_run: Callable[..., Any],
    ph: str,
    ip: str,
    reason: str,
    added_by: str,
) -> bool:
    """Insert IP suppression if missing; dismiss existing events. Returns True if added."""
    if not ip:
        return False
    existing = db_fetchone(
        f"SELECT id FROM siem_suppression WHERE suppress_type={ph} AND value={ph}",
        ("ip", ip),
    )
    if not existing:
        db_run(
            f"INSERT INTO siem_suppression (suppress_type, value, reason, added_by) "
            f"VALUES ({ph},{ph},{ph},{ph})",
            ("ip", ip, reason, added_by),
        )
    db_run(
        f"UPDATE siem_events SET dismissed=1 WHERE src_ip={ph} AND dismissed=0",
        (ip,),
    )
    return True


def _resolve_finding(
    db_fetchone: Callable[..., Any],
    db_run: Callable[..., Any],
    ph: str,
    finding_id: int,
    notes: str,
    username: str,
) -> bool:
    """Mark finding resolved as false_positive if still open."""
    row = db_fetchone(
        f"SELECT id, resolved FROM system_findings WHERE id={ph}",
        (finding_id,),
    )
    if not row or row.get("resolved"):
        return False
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    db_run(
        f"UPDATE system_findings SET resolved=1, resolved_at={ph}, "
        f"resolution_reason={ph}, resolution_notes={ph}, resolved_by={ph} "
        f"WHERE id={ph}",
        (now_str, "false_positive", notes[:500], username, finding_id),
    )
    return True


def _finding_context(
    db_fetchone: Callable[..., Any],
    db_fetchall: Callable[..., Any],
    ph: str,
    finding_id: int,
) -> dict[str, Any] | None:
    """Load finding row plus best-effort src_ip from description or recent events."""
    f = db_fetchone(f"SELECT * FROM system_findings WHERE id={ph}", (finding_id,))
    if not f:
        return None
    desc = (f.get("description") or "") + " " + (f.get("title") or "")
    ip = extract_first_ipv4(desc)
    if not ip:
        ev = db_fetchall(
            f"SELECT src_ip FROM siem_events WHERE dismissed=0 AND src_ip != '' "
            f"ORDER BY id DESC LIMIT 50"
        )
        for row in ev or []:
            candidate = (row.get("src_ip") or "").strip()
            if candidate:
                ip = candidate
                break
    return {"finding": f, "src_ip": ip, "text": desc}


def apply_template(
    template_id: str,
    finding_id: int,
    *,
    db_fetchone: Callable[..., Any],
    db_fetchall: Callable[..., Any],
    db_run: Callable[..., Any],
    ph: str,
    added_by: str = "analyst",
) -> dict[str, Any]:
    """
    Run a registered FP template. Returns {ok, error?, actions_taken, suppressed?, finding_resolved?}.
    """
    if template_id not in TEMPLATE_IDS:
        return {"ok": False, "error": f"Unknown template_id: {template_id}"}

    ctx = _finding_context(db_fetchone, db_fetchall, ph, finding_id)
    if not ctx:
        return {"ok": False, "error": "Finding not found"}

    finding = ctx["finding"]
    title = (finding.get("title") or "")
    ip = ctx["src_ip"]
    actions: list[str] = []
    suppressed = False
    finding_resolved = False

    if template_id == "internet_port_scan":
        if "Firewall Port Scan" not in title and "firewall" not in title.lower():
            return {
                "ok": False,
                "error": "Template internet_port_scan expects a firewall port-scan style finding",
            }
        if not ip:
            return {"ok": False, "error": "Could not extract source IP from finding"}
        reason = "FP template: internet background port scan"
        suppressed = _ensure_suppression(
            db_fetchone, db_run, ph, ip, reason, added_by
        )
        if suppressed:
            actions.append(f"suppressed_ip:{ip}")
        finding_resolved = _resolve_finding(
            db_fetchone,
            db_run,
            ph,
            finding_id,
            "Closed via Quick FP: internet port scan (repeat scanner suppressed).",
            added_by,
        )
        if finding_resolved:
            actions.append("finding_resolved:false_positive")

    elif template_id == "documentation_test_ip":
        if not ip or not _is_documentation_ip(ip):
            return {
                "ok": False,
                "error": "No RFC5737 documentation IP (203.0.113.x, 198.51.100.x, 192.0.2.x) in finding",
            }
        reason = "FP template: documentation / lab test IP"
        suppressed = _ensure_suppression(
            db_fetchone, db_run, ph, ip, reason, added_by
        )
        if suppressed:
            actions.append(f"suppressed_ip:{ip}")
        finding_resolved = _resolve_finding(
            db_fetchone,
            db_run,
            ph,
            finding_id,
            "Closed via Quick FP: documentation test IP.",
            added_by,
        )
        if finding_resolved:
            actions.append("finding_resolved:false_positive")

    elif template_id == "expected_vendor_service":
        if "New Service Installed" not in title:
            return {
                "ok": False,
                "error": "Template expected_vendor_service applies to New Service Installed findings",
            }
        finding_resolved = _resolve_finding(
            db_fetchone,
            db_run,
            ph,
            finding_id,
            "Closed via Quick FP: expected vendor service (ingest tune handles future NEP/NordVPN noise).",
            added_by,
        )
        if finding_resolved:
            actions.append("finding_resolved:false_positive")

    if not actions:
        return {"ok": False, "error": "No actions applied (finding may already be closed)"}

    return {
        "ok": True,
        "template_id": template_id,
        "actions_taken": actions,
        "suppressed": suppressed,
        "finding_resolved": finding_resolved,
        "suppressed_ip": ip if suppressed else "",
    }
