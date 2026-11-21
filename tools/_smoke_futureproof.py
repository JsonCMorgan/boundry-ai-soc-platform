"""Smoke Futureproof Career routes (G13/G16/G17/G18/G21/G22)."""
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

tmp = Path(tempfile.mkdtemp()) / "fp_smoke.db"
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

results: list[tuple[str, bool]] = []

pages = [
    "/career/soar",
    "/career/oversight",
    "/career/tune",
    "/career/metrics",
    "/career/automation",
    "/career/automation-policy",
    "/career/skills",
]
for p in pages:
    r = c.get(p)
    results.append((f"GET {p}", r.status_code == 200))

# SOAR learn-coach fields + case page
import soar_career_lab

sc = soar_career_lab.get_scenario("sc_spray_block")
results.append((
    "SOAR coach fields",
    bool(
        sc
        and sc.get("enrich_coach")
        and sc.get("look_for")
        and sc.get("reason_scaffold")
        and sc.get("ticket_scaffold")
        and sc.get("secplus_href")
    ),
))
r = c.get("/career/soar")
hub_html = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "SOAR hub learn_note",
    r.status_code == 200 and "human-gate habit" in hub_html and "sp_d4_10_automation_soar" in hub_html,
))
r = c.get("/career/soar/sc_spray_block")
case_html = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "SOAR case coach UI",
    r.status_code == 200
    and "Insert reason scaffold" in case_html
    and "enrich_coach" not in case_html  # not leaking raw key; coach text is present
    and "Cite these facts" in case_html,
))

# Ticket Field Console — SOAR case UI + field grading
results.append((
    "SOAR ticket field console UI",
    r.status_code == 200
    and "ticket-console" in case_html
    and "TicketFields" in case_html
    and "Ticket fields" in case_html,
))
results.append((
    "SOAR ticket_fields on scenario",
    bool(sc and sc.get("ticket_fields") and sc.get("ticket_seed")),
))

_SPRAY_FIELDS = {
    "client": "Contoso",
    "priority": "p2",
    "disposition": "escalate",
    "what_happened": "Password spray with many failed logons from one IP",
    "evidence": "Enriched IOC 203.0.113.44 suspicious reputation, no allowlist",
    "actions_taken": "Approved 24h edge block on the source IP",
    "next_action": "Monitor for successful logons after the block",
}
r = c.post("/api/career/soar/grade", json={
    "scenario_id": "sc_spray_block",
    "enriched": True,
    "decision": "approve",
    "reason": "spray with no success yet, block the source",
    "ticket_fields": _SPRAY_FIELDS,
})
d = r.get_json() or {}
results.append(("SOAR grade with ticket fields", bool(d.get("ok") and d.get("passed"))))
results.append((
    "SOAR field_results present",
    bool(d.get("field_results") and d.get("composed_note")),
))

_MISSING = dict(_SPRAY_FIELDS)
_MISSING["evidence"] = "short"
_MISSING["next_action"] = ""
r = c.post("/api/career/soar/grade", json={
    "scenario_id": "sc_spray_block",
    "enriched": True,
    "decision": "approve",
    "reason": "spray with no success yet, block the source",
    "ticket_fields": _MISSING,
})
d = r.get_json() or {}
results.append(("SOAR missing ticket field fails", bool(d.get("ok") and not d.get("passed"))))

r = c.post("/api/career/soar/grade", json={
    "scenario_id": "sc_spray_block",
    "enriched": False,
    "decision": "approve",
    "reason": "spray with no success yet, block the source",
    "ticket_fields": _SPRAY_FIELDS,
})
d = r.get_json() or {}
results.append(("SOAR grade requires enrich", bool(d.get("ok") and not d.get("passed"))))

# Shift page mounts field console (client/disposition stay separate)
r = c.get("/career/shift")
shift_html = r.get_data(as_text=True) if r.status_code == 200 else ""
results.append((
    "Shift ticket field console",
    r.status_code == 200
    and "Ticket Field Console" in shift_html
    and "TicketFields" in shift_html
    and "TICKET_FIELDS" in shift_html,
))
import career_lab
import ticket_fields as _tf
_shift_fields = {
    "priority": "p2",
    "what_happened": "User reported phishing mail clicked",
    "evidence": "Message ID and sender domain in alert detail",
    "actions_taken": "Blocked sender and reset password",
    "next_action": "Watch mailbox rules for new forwards",
}
_hygiene_notes = _tf.compose_note({
    "client": "Contoso",
    "priority": "p2",
    "disposition": "true_positive",
    **_shift_fields,
})
results.append((
    "Shift compose_note hygiene length",
    career_lab._hygiene_ok(
        _shift_fields["what_happened"],
        _shift_fields["next_action"],
        _hygiene_notes,
    ),
))
results.append((
    "Shift fields omit client/disposition",
    all(f["id"] not in ("client", "disposition") for f in _tf.fields_for_ui(omit=["client", "disposition"])),
))

r = c.post("/api/career/oversight/grade", json={
    "case_id": "ao_tp_ransom",
    "action": "override_tp",
    "evidence_id": "note_mass",
})
d = r.get_json() or {}
results.append(("Oversight grade", bool(d.get("ok") and d.get("passed"))))

r = c.post("/api/career/tune/grade", json={"drill_id": "tn_scanner", "choice": "tune"})
d = r.get_json() or {}
results.append(("Tune grade", bool(d.get("ok") and d.get("passed"))))

r = c.post("/api/career/metrics/grade", json={
    "answers": {"mq1": "b", "mq2": "b", "mq3": "b"},
})
d = r.get_json() or {}
results.append(("Metrics grade", bool(d.get("ok") and d.get("passed"))))

r = c.post("/api/career/automation/grade", json={
    "drill_id": "al_extract", "ran_extract": True,
})
d = r.get_json() or {}
results.append(("Automation extract", bool(d.get("ok") and d.get("passed"))))

r = c.post("/api/career/policy/grade", json={
    "scenario_id": "pl_apply_harbor",
    "choice": "manual_contain",
})
d = r.get_json() or {}
results.append(("Policy grade", bool(d.get("ok") and d.get("passed"))))

failed = 0
for name, ok in results:
    print(f"[{'OK' if ok else 'FAIL'}] {name}")
    if not ok:
        failed += 1
if failed:
    print(f"FUTUREPROOF_SMOKE_FAIL {failed}/{len(results)}")
    sys.exit(1)
print(f"FUTUREPROOF_SMOKE_OK {len(results)}/{len(results)}")
