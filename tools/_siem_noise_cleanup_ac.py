"""One-shot: Option C cleanup after NordVPN 7045 tune (A).

- Retag historical NEP/NordVPN 7045 events as benign INFO
- Resolve open SIEM 'New Service Installed' findings
- Resolve open SIEM brute-force findings on documentation IPs
- Delete source=simulation events (training clutter)
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "app.db"
NEP_RE = re.compile(
    r"(Service Name:\s*NEP[A-Za-z0-9]+)|(NordVPN)|(NordLynx)|(nordsec)",
    re.I,
)


def main() -> None:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 1) Retag historical benign service installs
    rows = cur.execute(
        "SELECT id, description, event_type, severity FROM siem_events "
        "WHERE event_type IN ('service_installed','service_installed_benign') "
        "OR description LIKE '%NEP%' OR description LIKE '%NordVPN%'"
    ).fetchall()
    retagged = 0
    for r in rows:
        desc = r["description"] or ""
        if not NEP_RE.search(desc) and "NordVPN" not in desc and "NEP" not in desc:
            continue
        if r["event_type"] == "service_installed_benign" and r["severity"] == "INFO":
            continue
        new_desc = desc
        if "[tuned vendor noise]" not in desc:
            new_desc = desc.replace("Event 7045 —", "Event 7045 [tuned vendor noise] —", 1)
            if new_desc == desc:
                new_desc = f"[tuned vendor noise] {desc}"[:500]
        cur.execute(
            "UPDATE siem_events SET event_type=?, severity=?, description=? WHERE id=?",
            ("service_installed_benign", "INFO", new_desc, r["id"]),
        )
        retagged += 1

    # 2) Resolve SIEM New Service Installed findings (open)
    cur.execute(
        "UPDATE system_findings SET resolved=1, resolved_at=datetime('now'), "
        "resolution_reason=?, resolution_notes=?, resolved_by=? "
        "WHERE scan_type='siem' AND resolved=0 AND title LIKE ?",
        (
            "tuned",
            "NordVPN NEP helper / known vendor service noise (Option A+C cleanup)",
            "system",
            "%New Service Installed%",
        ),
    )
    svc_resolved = cur.rowcount

    # 3) Resolve brute-force findings on RFC5737 doc IPs (sim/SOAR lab)
    cur.execute(
        "UPDATE system_findings SET resolved=1, resolved_at=datetime('now'), "
        "resolution_reason=?, resolution_notes=?, resolved_by=? "
        "WHERE scan_type='siem' AND resolved=0 AND ("
        "title LIKE '%203.0.113.%' OR title LIKE '%198.51.100.%' OR title LIKE '%192.0.2.%')",
        (
            "tuned",
            "Documentation/sim IP noise cleanup (Option A+C)",
            "system",
        ),
    )
    bf_resolved = cur.rowcount

    # 4) Purge simulation source events
    cur.execute("SELECT COUNT(1) FROM siem_events WHERE source='simulation'")
    sim_before = cur.fetchone()[0]
    cur.execute("DELETE FROM siem_events WHERE source='simulation'")

    conn.commit()
    open_siem = cur.execute(
        "SELECT COUNT(1) FROM system_findings WHERE scan_type='siem' AND resolved=0"
    ).fetchone()[0]
    print(f"retagged_benign_7045={retagged}")
    print(f"resolved_service_findings={svc_resolved}")
    print(f"resolved_docip_bruteforce={bf_resolved}")
    print(f"deleted_simulation_events={sim_before}")
    print(f"open_siem_findings_left={open_siem}")
    conn.close()


if __name__ == "__main__":
    main()
