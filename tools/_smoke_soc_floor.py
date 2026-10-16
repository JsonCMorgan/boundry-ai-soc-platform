"""Smoke test Live SOC Floor (/soc) hybrid queue + case + shift."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ["SEED_DB"] = "true"
import app as app_module

tmp = Path(tempfile.mkdtemp()) / "soc_floor_smoke.db"
app_module.DB_PATH = tmp
app_module.init_db()
app_module.app.config["TESTING"] = True
app_module.app.config["WTF_CSRF_ENABLED"] = False
c = app_module.app.test_client()
PH = app_module.PH

app_module.db_run(
    f"UPDATE users SET role = {PH} WHERE username = {PH}",
    ("analyst", "admin"),
)
row = app_module.db_fetchone(
    f"SELECT id FROM users WHERE username = {PH}",
    ("admin",),
)
aid = row["id"]
with c.session_transaction() as sess:
    sess["username"] = "admin"
    sess["role"] = "analyst"
    sess["user_id"] = aid
    sess["analyst_mode"] = "ops"

results: list[tuple[str, int, bool]] = []

r = c.get("/soc")
html = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "soc page",
    r.status_code,
    r.status_code == 200 and "SOC Floor" in html and "Alert queue" in html,
))
results.append((
    "soc live ops shell",
    r.status_code,
    r.status_code == 200
    and "ops-topbar" in html
    and "ops-status-strip" in html
    and "TicketFields" in html
    and "ticket-console" in html,
))

r = c.get("/soc/tickets")
thtml = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "tickets ops table",
    r.status_code,
    r.status_code == 200
    and "ops-table" in thtml
    and "ops-topbar" in thtml
    and "<th>Ticket</th>" in thtml
    and "<th>Updated</th>" in thtml,
))

r = c.get("/control-room")
crhtml = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "control room live shell",
    r.status_code,
    r.status_code == 200
    and "ops-shell" in crhtml
    and "Control Room" in crhtml
    and "Open tickets" in crhtml
    and "ops-status-strip" in crhtml,
))

r = c.get("/api/soc/queue?lane=all")
d = r.get_json() or {}
results.append(("queue empty-or-list", r.status_code, bool(d.get("ok"))))

# Cases must work WITHOUT starting a shift first
r = c.post("/api/soc/practice/inject", json={"count": 4})
d = r.get_json() or {}
results.append(("practice inject", r.status_code, bool(d.get("ok") and int(d.get("injected") or 0) >= 1)))

r = c.get("/api/soc/queue?lane=practice")
d = r.get_json() or {}
items = d.get("items") or []
results.append(("practice queue", r.status_code, bool(d.get("ok") and len(items) >= 1 and items[0].get("is_practice"))))

prac0 = items[0]
r = c.post("/api/soc/cases/open", json={"source": prac0["source"], "source_id": prac0["source_id"]})
d = r.get_json() or {}
results.append((
    "open case without shift",
    r.status_code,
    bool(d.get("ok") and (d.get("case") or {}).get("id")),
))

r = c.post("/api/soc/shift/start", json={})
d = r.get_json() or {}
results.append(("shift start", r.status_code, bool(d.get("ok") and d.get("shift"))))

# Seed one real finding for real lane
app_module.db_run(
    f"INSERT INTO system_findings "
    f"(finding_id, title, severity, category, description, recommendation, raw_output, resolved, scan_type) "
    f"VALUES ({PH}, {PH}, {PH}, {PH}, {PH}, {PH}, {PH}, 0, {PH})",
    ("smoke-find-1", "Smoke open port", "HIGH", "network", "Port 445 open on lab host", "Close or justify", "{}", "network"),
)
r = c.get("/api/soc/queue?lane=real")
d = r.get_json() or {}
real_items = d.get("items") or []
has_real = any(not i.get("is_practice") for i in real_items)
results.append(("real queue has finding", r.status_code, bool(d.get("ok") and has_real)))

# Re-open / resume practice case (now with an active shift optional)
prac = items[0]
r = c.post("/api/soc/cases/open", json={"source": prac["source"], "source_id": prac["source_id"]})
d = r.get_json() or {}
case = d.get("case") or {}
results.append(("open practice case", r.status_code, bool(d.get("ok") and case.get("id") and d.get("context"))))

cid = case.get("id")
ticket_no = case.get("ticket_no") or ""
results.append(("ticket_no minted", 200, bool(str(ticket_no).startswith("BT-"))))

r = c.post(
    f"/api/soc/cases/{cid}",
    json={
        "summary": "Practice spray pattern from one IP",
        "next_action": "Block src and watch for 4624",
        "enrich_notes": "IOC pending",
        "disposition": "true_positive",
        "priority": 2,
    },
)
d = r.get_json() or {}
results.append((
    "save case",
    r.status_code,
    bool(d.get("ok") and (d.get("case") or {}).get("status") == "working"),
))

# Escalate as living state (must not close)
r = c.post(
    f"/api/soc/cases/{cid}/transition",
    json={"to": "escalated", "note": "Escalate to Tier-2: need IR for Contoso spray persistence."},
)
d = r.get_json() or {}
results.append((
    "escalate living state",
    r.status_code,
    bool(d.get("ok") and (d.get("case") or {}).get("status") == "escalated"),
))

r = c.post(
    f"/api/soc/cases/{cid}/transition",
    json={"to": "working", "note": "Resuming after Tier-2 ack."},
)
d = r.get_json() or {}
results.append((
    "resume from escalated",
    r.status_code,
    bool(d.get("ok") and (d.get("case") or {}).get("status") == "working"),
))

r = c.post(
    f"/api/soc/cases/{cid}/comment",
    json={"body": "Human work note on timeline."},
)
d = r.get_json() or {}
tl = d.get("timeline") or []
results.append((
    "timeline comment",
    r.status_code,
    bool(d.get("ok") and any(e.get("event_type") == "comment" for e in tl)),
))

r = c.post(
    f"/api/soc/cases/{cid}/close",
    json={
        "summary": "Practice spray pattern from one IP",
        "next_action": "Block src and watch for 4624",
        "disposition": "true_positive",
    },
)
d = r.get_json() or {}
results.append(("close case", r.status_code, bool(d.get("ok") and (d.get("case") or {}).get("status") == "closed")))

r = c.get("/soc/tickets?status=closed")
results.append(("tickets list page", r.status_code, r.status_code == 200 and b"Boundry Tickets" in r.data))

r = c.get("/api/soc/tickets?status=closed")
d = r.get_json() or {}
results.append(("tickets api", r.status_code, bool(d.get("ok") and d.get("count", 0) >= 1)))

# Real finding case + resolve
find = next(i for i in real_items if i.get("source") == "finding")
r = c.post("/api/soc/cases/open", json={"source": "finding", "source_id": find["source_id"]})
d = r.get_json() or {}
fcid = (d.get("case") or {}).get("id")
results.append(("open finding case", r.status_code, bool(d.get("ok") and fcid)))

r = c.post(f"/api/soc/cases/{fcid}/resolve-finding", json={})
d = r.get_json() or {}
results.append(("resolve finding", r.status_code, bool(d.get("ok"))))

r = c.post("/api/soc/enrich", json={"ioc": "8.8.8.8"})
d = r.get_json() or {}
results.append(("enrich stub", r.status_code, bool(d.get("ok") and d.get("verdict") == "benign")))

r = c.post(
    "/api/soc/shift/end",
    json={"handoff_note": "Closed practice spray. Finding smoke-find-1 resolved. No open CRITICAL left for Boundry-Host."},
)
d = r.get_json() or {}
results.append(("shift end", r.status_code, bool(d.get("ok"))))

# Analyst presence: Arrived → GET; SIEM event written
r = c.post("/api/ops/presence", json={"action": "arrived"})
d = r.get_json() or {}
results.append((
    "presence arrived",
    r.status_code,
    bool(d.get("ok") and d.get("presence") == "arrived"),
))
r = c.get("/api/ops/presence")
d = r.get_json() or {}
results.append((
    "presence get",
    r.status_code,
    bool(d.get("ok") and d.get("presence") == "arrived" and isinstance(d.get("recent"), list)),
))
pres_row = app_module.db_fetchone(
    f"SELECT id, event_type FROM siem_events "
    f"WHERE event_type = {PH} AND user_account = {PH} ORDER BY id DESC LIMIT 1",
    ("analyst_presence_arrived", "admin"),
)
results.append((
    "presence siem event",
    200,
    bool(pres_row and pres_row.get("event_type") == "analyst_presence_arrived"),
))
r = c.post("/api/ops/presence", json={"action": "away"})
d = r.get_json() or {}
results.append(("presence away", r.status_code, bool(d.get("ok") and d.get("presence") == "away")))

# UI chip mounted
r = c.get("/soc")
results.append((
    "soc presence chip",
    r.status_code,
    r.status_code == 200 and b"ops-presence" in r.data and b"OpsPresence" in r.data,
))
r = c.get("/control-room")
results.append((
    "cr presence chip",
    r.status_code,
    r.status_code == 200 and b"ops-presence" in r.data and b"OpsPresence" in r.data,
))

# Control Room HQ Attention (ops mode: MITRE encyclopedia hidden)
with c.session_transaction() as sess:
    sess["analyst_mode"] = "ops"
r = c.get("/control-room")
cr_ops = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "cr hq attention",
    r.status_code,
    r.status_code == 200
    and "hq-attention" in cr_ops
    and "Attention · Tickets" in cr_ops
    and "hq-kpi" in cr_ops
    and "hq-tools" in cr_ops,
))
_mitre_marker = "MITRE ATT&amp;CK Reference"
results.append((
    "cr ops hides mitre encyclopedia",
    r.status_code,
    r.status_code == 200 and _mitre_marker not in cr_ops,
))
with c.session_transaction() as sess:
    sess["analyst_mode"] = "study"
r = c.get("/control-room")
cr_study = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "cr study shows mitre encyclopedia",
    r.status_code,
    r.status_code == 200 and _mitre_marker in cr_study,
))

# Nav link present on control room or soc
r = c.get("/soc")
results.append(("nav soc floor", r.status_code, b"SOC Floor" in r.data))

failed = 0
for name, code, ok in results:
    mark = "OK" if ok else "FAIL"
    if not ok:
        failed += 1
    print(f"[{mark}] {name} (http {code})")

if failed:
    print(f"SOC_FLOOR_SMOKE_FAIL {failed}/{len(results)}")
    sys.exit(1)
print(f"SOC_FLOOR_SMOKE_OK {len(results)}/{len(results)}")
