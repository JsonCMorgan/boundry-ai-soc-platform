"""
G8 — Log source literacy lab.

Option A (hire-aligned, simplest): flashcards for common sources +
"name the evidence" drills (Windows 4625/4688, firewall, proxy, M365).
Original Boundry samples only. Terms defined before use.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Log Source Lab"
TRACK_BLURB = (
    "Learn to name what a log line proves. Employers ask you to read Windows "
    "Security events, firewall denials, proxy clicks, and Microsoft 365 sign-ins "
    "without guessing. Flashcards first, then prove-it drills."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "Log source",
        "plain": "Where the record came from (Windows Security, firewall, web proxy, Microsoft 365). Different sources use different field names.",
    },
    {
        "term": "Event ID",
        "plain": "A number Windows uses to label a Security log record. Example: 4625 means a failed logon.",
    },
    {
        "term": "Evidence",
        "plain": "The fact the log proves (failed password, new process, blocked connection). You cite evidence in tickets, not vibes.",
    },
    {
        "term": "False positive risk",
        "plain": "A noisy pattern that looks bad but is often expected (scanner traffic, service accounts). Still document what the log says.",
    },
]

# Flashcards shown on the hub (Show me)
FLASHCARDS: list[dict[str, str]] = [
    {
        "front": "Windows Security 4625",
        "back": "Failed logon. Look at Account Name, Source Network Address, Failure Reason, and Logon Type (3 = network).",
    },
    {
        "front": "Windows Security 4688",
        "back": "A new process was created. Parent process + New Process Name + Command Line are the evidence chain.",
    },
    {
        "front": "Windows Security 4624",
        "back": "Successful logon. Useful with 4625 bursts (spray) or odd Logon Type / source IP after hours.",
    },
    {
        "front": "Firewall deny",
        "back": "Packet blocked by host or edge firewall. Cite src/dst IP, port, and action=DROP/DENY.",
    },
    {
        "front": "Web proxy allow/deny",
        "back": "User or host requested a URL through a proxy. Cite user, URL category or reputation, and HTTP status.",
    },
    {
        "front": "Microsoft 365 sign-in",
        "back": "Cloud identity authentication record. Cite user, IP, app, result (Success/Failure), and Conditional Access outcome when present.",
    },
]


def _drill(
    did: str,
    title: str,
    difficulty: int,
    source_id: str,
    evidence_id: str,
    teach: str,
    snippet: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": did,
        "title": title,
        "difficulty": difficulty,
        "correct_source": source_id,
        "correct_evidence": evidence_id,
        "teach": teach,
        "snippet": snippet.strip() + "\n",
        "checklist_answers": checklist,
    }


DRILLS: list[dict[str, Any]] = [
    _drill(
        "win_4625_spray",
        "Failed logons from one IP",
        1,
        "windows_security",
        "failed_logon_4625",
        "Many 4625s from one Source Network Address against different accounts is classic password spray evidence.",
        """
EventID: 4625
Account Name: j.patel
Account Domain: CONTOSO
Logon Type: 3
Source Network Address: 203.0.113.44
Failure Reason: Unknown user name or bad password
Status: 0xC000006D
Workstation Name: -
Message: An account failed to log on.
---
EventID: 4625
Account Name: a.morgan
Account Domain: CONTOSO
Logon Type: 3
Source Network Address: 203.0.113.44
Failure Reason: Unknown user name or bad password
""",
        {
            "names_event_id": True,
            "cites_src_ip": True,
            "multiple_accounts": True,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "win_4688_ps",
        "PowerShell child of Excel",
        1,
        "windows_security",
        "process_create_4688",
        "4688 shows process creation. Parent Image + New Process Name + Command Line are what you put in the ticket.",
        """
EventID: 4688
Creator Process Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE
New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
Process Command Line: powershell.exe -NoP -Enc JABzAD0ATgBlAHcALg4uLg==
Subject User Name: j.patel
Computer: WS-HR-03
""",
        {
            "names_event_id": True,
            "cites_src_ip": False,
            "multiple_accounts": False,
            "process_create_not_primary": True,
        },
    ),
    _drill(
        "fw_outbound_c2",
        "Firewall deny to rare port",
        2,
        "firewall",
        "firewall_deny",
        "A deny to an unusual destination port from a workstation is evidence of blocked egress, not proof of malware by itself. Still ticket the 5-tuple.",
        """
2026-10-03 14:22:11 DROP TCP 10.20.30.55:51884 -> 198.51.100.77:4444
action=DENY rule=block-suspicious-egress
src_host=WS-FINANCE-12 dst_port=4444 proto=TCP
""",
        {
            "names_event_id": False,
            "cites_src_ip": True,
            "multiple_accounts": False,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "proxy_phish_click",
        "Proxy hit to lookalike URL",
        2,
        "proxy",
        "proxy_url_hit",
        "Proxy logs prove a URL request happened. Pair with email case notes. Do not invent a successful download without HTTP status evidence.",
        """
time=2026-10-03T09:11:04Z user=ap.clerk@clientcorp.example
src_ip=10.20.30.88 method=GET
url=https://c0ntoso-finance.com/wire-approve
category=newly_registered action=ALLOW http_status=200
user_agent=Mozilla/5.0
""",
        {
            "names_event_id": False,
            "cites_src_ip": True,
            "multiple_accounts": False,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "m365_impossible",
        "M365 success from distant IP",
        2,
        "m365",
        "m365_signin",
        "Cloud sign-in logs prove authentication result and source IP/app. Flag geography/time anomalies and check Conditional Access when present.",
        """
Operation: UserLoggedIn
UserId: a.morgan@contoso.com
ClientIP: 45.77.12.200
AppDisplayName: Office 365 Exchange Online
ResultStatus: Success
Location: Lagos, NG
ConditionalAccessStatus: notApplied
DeviceDetail: Browser
""",
        {
            "names_event_id": False,
            "cites_src_ip": True,
            "multiple_accounts": False,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "win_4624_rdp",
        "Successful RDP logon (4624 type 10)",
        1,
        "windows_security",
        "successful_logon_4624",
        "4624 with Logon Type 10 is interactive remote desktop success. Cite account, source IP, and workstation in the ticket.",
        """
EventID: 4624
Account Name: svc_helpdesk
Account Domain: CONTOSO
Logon Type: 10
Source Network Address: 10.20.30.12
Workstation Name: WS-IT-02
Logon Process: User32
Authentication Package: Negotiate
Computer: WS-FINANCE-12
Message: An account was successfully logged on.
""",
        {
            "names_event_id": True,
            "cites_src_ip": True,
            "multiple_accounts": False,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "linux_sudo_fail",
        "Linux sudo failures in auth.log",
        2,
        "linux_auth",
        "linux_auth_fail",
        "Linux auth.log sudo/auth failures are the Linux cousin of Windows failed logons. Name the source as linux auth and cite the user + src IP.",
        """
Oct  8 02:14:11 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1001 euid=0 tty=/dev/pts/0 ruser=deploy rhost=203.0.113.44 user=deploy
Oct  8 02:14:13 web01 sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1001 euid=0 tty=/dev/pts/0 ruser=deploy rhost=203.0.113.44 user=root
Oct  8 02:14:15 web01 sshd[4412]: Failed password for invalid user admin from 203.0.113.44 port 51822 ssh2
""",
        {
            "names_event_id": False,
            "cites_src_ip": True,
            "multiple_accounts": True,
            "process_create_not_primary": False,
        },
    ),
    _drill(
        "fw_inbound_scan",
        "Firewall denies inbound scan burst",
        2,
        "firewall",
        "firewall_deny",
        "Inbound DENY bursts from one internet IP across many ports is scan noise unless a later ALLOW succeeds. Still ticket the source and top ports.",
        """
2026-10-08 03:01:11 DROP TCP 198.51.100.200:40011 -> 203.0.113.10:22
2026-10-08 03:01:11 DROP TCP 198.51.100.200:40012 -> 203.0.113.10:80
2026-10-08 03:01:12 DROP TCP 198.51.100.200:40013 -> 203.0.113.10:443
2026-10-08 03:01:12 DROP TCP 198.51.100.200:40014 -> 203.0.113.10:3389
action=DENY rule=edge-default-deny src=198.51.100.200
""",
        {
            "names_event_id": False,
            "cites_src_ip": True,
            "multiple_accounts": False,
            "process_create_not_primary": False,
        },
    ),
]

SOURCES = [
    {"id": "windows_security", "label": "Windows Security log"},
    {"id": "firewall", "label": "Firewall / network filter log"},
    {"id": "proxy", "label": "Web proxy / secure web gateway"},
    {"id": "m365", "label": "Microsoft 365 / Entra sign-in log"},
    {"id": "linux_auth", "label": "Linux auth.log / secure"},
]

EVIDENCE_TYPES = [
    {
        "id": "failed_logon_4625",
        "label": "Failed logon (Windows Event ID 4625)",
    },
    {
        "id": "process_create_4688",
        "label": "Process creation (Windows Event ID 4688)",
    },
    {
        "id": "firewall_deny",
        "label": "Firewall deny / drop of a connection",
    },
    {
        "id": "proxy_url_hit",
        "label": "Proxy URL request (user/host fetched a site)",
    },
    {
        "id": "m365_signin",
        "label": "Cloud identity sign-in (success or failure)",
    },
    {
        "id": "successful_logon_4624",
        "label": "Successful logon (Windows Event ID 4624)",
    },
    {
        "id": "linux_auth_fail",
        "label": "Linux auth failure (sshd / sudo / pam)",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "names_event_id",
        "label": "Snippet includes a Windows Event ID (or clearly names EventID)",
    },
    {
        "id": "cites_src_ip",
        "label": "Snippet includes a source IP / ClientIP / Source Network Address worth citing",
    },
    {
        "id": "multiple_accounts",
        "label": "Evidence shows more than one account targeted (spray-style pattern)",
    },
    {
        "id": "process_create_not_primary",
        "label": "Primary evidence is process creation (parent → child / command line), not authentication",
    },
]


def drill_ids() -> list[str]:
    """Ordered drill ids for next-scenario rotation."""
    return [d["id"] for d in DRILLS]


def list_drills() -> list[dict[str, Any]]:
    """Hub cards without snippets."""
    return [
        {
            "id": d["id"],
            "title": d["title"],
            "difficulty": d["difficulty"],
            "teach": d["teach"],
        }
        for d in DRILLS
    ]


def get_drill(drill_id: str) -> dict[str, Any] | None:
    """Return one drill including snippet (canonical, no variants)."""
    for d in DRILLS:
        if d["id"] == drill_id:
            return d
    return None


def materialize_drill(drill_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new hosts/users/IPs in the log snippet."""
    drill = get_drill(drill_id)
    if not drill:
        return None
    return career_instances.materialize_generic(
        drill,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["snippet", "teach"],
        allow_ip=True,
    )


def next_after(drill_id: str) -> dict[str, str]:
    """Random different drill + fresh seed under /career/logs."""
    return career_instances.next_scenario(drill_ids(), drill_id, "/career/logs")


def grade_drill(
    drill_id: str,
    source_id: str,
    evidence_id: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    """Grade source + evidence type + checklist."""
    drill = get_drill(drill_id)
    if not drill:
        return {"ok": False, "error": "Unknown drill"}
    answers = drill["checklist_answers"]
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
    source_ok = (source_id or "").strip() == drill["correct_source"]
    evidence_ok = (evidence_id or "").strip() == drill["correct_evidence"]
    # Checklist 4 + source 2 + evidence 2
    score = hit + (2 if source_ok else 0) + (2 if evidence_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    src_meta = next((s for s in SOURCES if s["id"] == drill["correct_source"]), None)
    ev_meta = next(
        (e for e in EVIDENCE_TYPES if e["id"] == drill["correct_evidence"]), None
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "source_correct": source_ok,
        "correct_source": drill["correct_source"],
        "evidence_correct": evidence_ok,
        "correct_evidence": drill["correct_evidence"],
        "teach": drill["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="source",
                label=(src_meta or {}).get("label") or drill["correct_source"],
                matched=source_ok,
                rationale=(
                    f"This snippet comes from the {(src_meta or {}).get('label') or 'named'} "
                    f"source. For this drill: {drill['teach']}"
                ),
                title="Why this log source",
                row_label="Correct log source",
            ),
            career_rationale.chip(
                id="evidence",
                label=(ev_meta or {}).get("label") or drill["correct_evidence"],
                matched=evidence_ok,
                rationale=(
                    f"Name the evidence type the snippet proves. "
                    f"For this drill: {drill['teach']}"
                ),
                title="Why this evidence type",
                row_label="Correct evidence type",
            ),
        ],
    }
