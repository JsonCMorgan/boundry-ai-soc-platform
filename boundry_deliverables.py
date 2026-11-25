"""Client deliverables: weekly digest email bodies and monthly summary content."""

from __future__ import annotations

from typing import Any, Callable


def weekly_digest_rows(
    db_fetchall: Callable[..., list],
    ph: str,
    postgres: bool,
) -> list[dict]:
    """Clients opted in to email alerts."""
    return db_fetchall(
        f"SELECT id, username, email, email_alerts FROM users "
        f"WHERE role = 'client' AND email != '' AND email_alerts = 1"
    ) or []


def build_weekly_digest_html(
    db_fetchall: Callable[..., list],
    ph: str,
    postgres: bool,
    user_id: int,
    username: str,
    app_url: str,
    health: dict,
) -> tuple[str, str]:
    """Return (subject, html_body) for one client's weekly digest."""
    if postgres:
        week_reports = db_fetchall(
            f"SELECT threat_count, status, simulated FROM reports "
            f"WHERE owner_id = {ph} AND simulated = 0 "
            f"AND created_at >= NOW() - INTERVAL '7 days'",
            (user_id,),
        )
    else:
        week_reports = db_fetchall(
            f"SELECT threat_count, status, simulated FROM reports "
            f"WHERE owner_id = {ph} AND simulated = 0 "
            f"AND created_at >= datetime('now', '-7 days')",
            (user_id,),
        )
    week_reports = week_reports or []
    report_count = len(week_reports)
    total_threats = sum(r.get("threat_count") or 0 for r in week_reports)
    open_count = sum(
        1 for r in week_reports if (r.get("status") or "new") not in ("closed",)
    )

    if report_count == 0:
        status_line = "No security incidents were detected this week — your systems are clear."
        action_line = "No action is needed."
    elif total_threats == 0:
        status_line = (
            f"{report_count} monitoring scan(s) completed this week — no threats found."
        )
        action_line = "Your environment looks healthy. No action is needed."
    else:
        status_line = (
            f"{total_threats} threat(s) across {report_count} scan(s) this week."
        )
        action_line = (
            f"{open_count} report(s) still need review."
            if open_count
            else "All incidents reviewed."
        )

    subject = f"Boundry.AI weekly digest — {username}"
    html_body = f"""<p>Hi {username},</p>
<p><strong>{status_line}</strong></p>
<p>{action_line}</p>
<p>Health score: {health.get('score', '—')}</p>
<p><a href="{app_url}/client/status">View monitoring status</a></p>"""
    return subject, html_body


def build_monthly_summary_markdown(
    db_fetchall: Callable[..., list],
    ph: str,
    postgres: bool,
    user_id: int,
    username: str,
    tenant_slug: str,
) -> tuple[str, int, int]:
    """Aggregate last 30 days; return (markdown, threat_count, event_count)."""
    if postgres:
        events = db_fetchall(
            f"SELECT severity FROM siem_events WHERE client_id = {ph} "
            f"AND simulated = 0 AND created_at >= NOW() - INTERVAL '30 days'",
            (tenant_slug,),
        )
        findings = db_fetchall(
            f"SELECT severity, title FROM system_findings WHERE client_id = {ph} "
            f"AND resolved = 0",
            (tenant_slug,),
        )
    else:
        events = db_fetchall(
            f"SELECT severity FROM siem_events WHERE client_id = {ph} "
            f"AND simulated = 0 AND created_at >= datetime('now', '-30 days')",
            (tenant_slug,),
        )
        findings = db_fetchall(
            f"SELECT severity, title FROM system_findings WHERE client_id = {ph} "
            f"AND resolved = 0",
            (tenant_slug,),
        )
    events = events or []
    findings = findings or []
    sev_counts: dict[str, int] = {}
    for e in events:
        s = (e.get("severity") or "INFO").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    threat_count = sev_counts.get("HIGH", 0) + sev_counts.get("CRITICAL", 0)
    event_count = len(events)

    lines = [
        f"# Monthly security summary — {username}",
        "",
        f"Period: last 30 days (tenant `{tenant_slug}`).",
        "",
        "## Event volume by severity",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = sev_counts.get(sev, 0)
        if n:
            lines.append(f"- **{sev}:** {n}")
    if not sev_counts:
        lines.append("- No SIEM events in period.")
    lines.append("")
    lines.append("## Open findings")
    if findings:
        for f in findings[:15]:
            lines.append(f"- [{f.get('severity')}] {f.get('title')}")
    else:
        lines.append("- None open.")
    lines.append("")
    lines.append("## Next steps")
    lines.append("1. Review any HIGH or CRITICAL items with your Boundry analyst.")
    lines.append("2. Confirm MFA on remote access and file-transfer accounts.")
    lines.append("3. Test an offline backup restore this month.")
    return "\n".join(lines), threat_count, event_count