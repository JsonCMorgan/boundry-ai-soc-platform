"""Quick SIEM noise snapshot (read-only)."""
from __future__ import annotations

import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "app.db"


def main() -> None:
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    print("TOTAL", conn.execute("SELECT COUNT(*) FROM siem_events").fetchone()[0])
    print(
        "LAST_24H",
        conn.execute(
            "SELECT COUNT(*) FROM siem_events WHERE created_at >= datetime('now','-1 day')"
        ).fetchone()[0],
    )
    print(
        "LAST_1H",
        conn.execute(
            "SELECT COUNT(*) FROM siem_events WHERE created_at >= datetime('now','-1 hour')"
        ).fetchone()[0],
    )
    print("---BY SOURCE (24h)---")
    for r in conn.execute(
        "SELECT source, COUNT(*) c FROM siem_events "
        "WHERE created_at >= datetime('now','-1 day') "
        "GROUP BY source ORDER BY c DESC"
    ):
        print(f"{r['c']:6} {r['source']}")
    print("---BY TYPE (24h top 25)---")
    for r in conn.execute(
        "SELECT event_type, COUNT(*) c FROM siem_events "
        "WHERE created_at >= datetime('now','-1 day') "
        "GROUP BY event_type ORDER BY c DESC LIMIT 25"
    ):
        print(f"{r['c']:6} {r['event_type']}")
    print("---BY SEVERITY (24h)---")
    for r in conn.execute(
        "SELECT severity, COUNT(*) c FROM siem_events "
        "WHERE created_at >= datetime('now','-1 day') "
        "GROUP BY severity ORDER BY c DESC"
    ):
        print(f"{r['c']:6} {r['severity']}")
    print("---SAMPLE (last 20)---")
    for r in conn.execute(
        "SELECT created_at, source, event_type, severity, description "
        "FROM siem_events ORDER BY id DESC LIMIT 20"
    ):
        d = (r["description"] or "")[:100]
        print(
            f"{r['created_at']} | {r['severity']:8} | {r['source']:14} | "
            f"{r['event_type']:28} | {d}"
        )
    print("---SUPPRESSION---")
    try:
        for r in conn.execute("SELECT * FROM siem_suppression LIMIT 50"):
            print(dict(r))
    except Exception as exc:
        print("suppression_err", exc)
    print("---RULES---")
    try:
        cols = [c[1] for c in conn.execute("PRAGMA table_info(siem_rules)")]
        print("cols", cols)
        for r in conn.execute("SELECT * FROM siem_rules"):
            print(dict(r))
    except Exception as exc:
        print("rules_err", exc)

    print("---ALLTIME BY TYPE TOP---")
    for r in conn.execute(
        "SELECT event_type, COUNT(1) c FROM siem_events "
        "GROUP BY event_type ORDER BY c DESC LIMIT 15"
    ):
        print(f"{r['c']:6} {r['event_type']}")
    nep = conn.execute(
        "SELECT COUNT(1) FROM siem_events WHERE description LIKE '%NEP%'"
    ).fetchone()[0]
    svc = conn.execute(
        "SELECT COUNT(1) FROM siem_events WHERE event_type='service_installed'"
    ).fetchone()[0]
    print(f"NEP_in_desc={nep} service_installed={svc}")
    print("---SIEM FINDINGS---")
    cols = [c[1] for c in conn.execute("PRAGMA table_info(system_findings)")]
    print("finding_cols", cols)
    if "scan_type" in cols:
        print(
            "siem_findings",
            conn.execute(
                "SELECT COUNT(1) FROM system_findings WHERE scan_type='siem'"
            ).fetchone()[0],
        )
        for r in conn.execute(
            "SELECT id, title, severity, created_at FROM system_findings "
            "WHERE scan_type='siem' ORDER BY id DESC LIMIT 15"
        ):
            print(dict(r))


if __name__ == "__main__":
    main()
