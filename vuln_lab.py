"""
G7 — Vulnerability scan triage queue.

Option A (hire-aligned, simplest): practice tickets that force CVSS vs
exploitability vs asset criticality. Not "run a scanner." Original Boundry
findings only. Terms defined before use.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Vulnerability Queue"
TRACK_BLURB = (
    "Practice how L1 supports vulnerability work: read a finding, weigh score "
    "against real-world exploitability and how important the asset is, then "
    "write a ticket disposition. This is triage judgment, not scanning."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "Vulnerability",
        "plain": "A weakness in software or config that an attacker might use. A scanner finding is a candidate, not automatically an emergency.",
    },
    {
        "term": "CVSS",
        "plain": "Common Vulnerability Scoring System: a 0–10 severity number vendors publish. High CVSS means the weakness can be severe in theory, not that every host is on fire.",
    },
    {
        "term": "Exploitability",
        "plain": "How easy it is to abuse right now (public exploit, wormable, needs local access). Sometimes a medium CVSS with a public exploit outranks a high CVSS with no exploit.",
    },
    {
        "term": "Asset criticality",
        "plain": "How bad it is if this host fails or is compromised (domain controller, payroll, internet-facing). Critical assets jump the queue.",
    },
    {
        "term": "Disposition",
        "plain": "What you recommend next: patch now, schedule, accept risk with owner, or false positive / not applicable.",
    },
]


def _case(
    cid: str,
    title: str,
    difficulty: int,
    finding: str,
    teach: str,
    priority_id: str,
    disposition: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": cid,
        "title": title,
        "difficulty": difficulty,
        "finding": finding.strip(),
        "teach": teach,
        "correct_priority": priority_id,
        "correct_disposition": disposition,
        "checklist_answers": checklist,
    }


CASES: list[dict[str, Any]] = [
    _case(
        "rdp_internet_critical",
        "RDP open on internet-facing jump box",
        1,
        """
CVE: CVE-2019-0708 style finding (practice label: Boundry-RDP-Weak)
CVSS: 9.8
Exploitability: Public remote exploit tooling widely known
Asset: JUMP-DMZ-01 (internet-facing remote access). Criticality: HIGH (path into corp)
Evidence: Port 3389 reachable from 0.0.0.0/0 on edge firewall rule review
""",
        "High CVSS + public exploit + internet-facing critical asset = patch/contain now, not 'schedule next month'.",
        "p1_immediate",
        "patch_now_escalate",
        {
            "high_cvss": True,
            "public_exploit": True,
            "critical_or_internet": True,
            "internal_only_low": False,
        },
    ),
    _case(
        "office_lib_medium",
        "Old Office DLL on HR laptop",
        1,
        """
Finding: Outdated Microsoft Office component
CVSS: 7.8 (local privilege / user interaction)
Exploitability: Needs user to open a crafted file; no wormable remote exploit in stub
Asset: WS-HR-03 (standard laptop). Criticality: LOW–MEDIUM
Compensating: EDR on host, mail gateway rewriting macros
""",
        "High-ish CVSS with user interaction and a non-critical laptop usually means schedule patch / standard SLA, not emergency IR.",
        "p3_schedule",
        "schedule_patch",
        {
            "high_cvss": True,
            "public_exploit": False,
            "critical_or_internet": False,
            "internal_only_low": False,
        },
    ),
    _case(
        "smb_signing_dc",
        "SMB signing disabled on domain controller",
        2,
        """
Finding: SMB signing not required
CVSS: 5.9 (medium)
Exploitability: Relay / downgrade paths exist in many AD environments when signing is off
Asset: DC01.contoso.local. Criticality: CRITICAL (identity plane)
Exposure: Internal only (not internet-facing)
""",
        "Medium CVSS on a domain controller with known attack paths still warrants high priority remediation planning. Criticality beats the number alone.",
        "p2_urgent",
        "patch_now_escalate",
        {
            "high_cvss": False,
            "public_exploit": True,
            "critical_or_internet": True,
            "internal_only_low": False,
        },
    ),
    _case(
        "dev_tool_fp",
        "Dev box reports 'vulnerable' self-signed cert scanner noise",
        2,
        """
Finding: SSL certificate self-signed / expired on localhost:8443
CVSS: n/a (config hygiene)
Exploitability: Localhost only; no external listeners
Asset: DEV-WS-LAB (developer workstation). Criticality: LOW
Owner note: Expected for local test harness; not a production service
""",
        "Localhost-only lab noise on a low-criticality asset is often false positive / accept with owner, not a patch-now fire drill.",
        "p4_accept_or_fp",
        "accept_or_fp",
        {
            "high_cvss": False,
            "public_exploit": False,
            "critical_or_internet": False,
            "internal_only_low": True,
        },
    ),
    _case(
        "exchange_proxy_style",
        "Internet-facing mail relay with known vuln class",
        1,
        """
CVE: Boundry-EXCH-Proxy style finding (practice label)
CVSS: 9.8
Exploitability: Public PoCs and scanning in the wild (stub)
Asset: MAIL-EDGE-01 (internet-facing Exchange / mail relay). Criticality: CRITICAL
Evidence: Edge scanner hit; vendor advisory says patch within 48h
""",
        "Internet mail edge + critical CVSS + active exploit class is P1 patch/contain, not a monthly window.",
        "p1_immediate",
        "patch_now_escalate",
        {
            "high_cvss": True,
            "public_exploit": True,
            "critical_or_internet": True,
            "internal_only_low": False,
        },
    ),
    _case(
        "printer_internal_low",
        "Old printer firmware on isolated VLAN",
        1,
        """
Finding: Outdated printer firmware
CVSS: 8.1 (network, no auth in advisory text)
Exploitability: Theoretical for this model; no active exploit in stub feed
Asset: PRT-FLOOR-3 on PRINT-VLAN (no route to internet or domain controllers)
Criticality: LOW
Compensating: VLAN ACL denies SMB/RDP from printers to servers
""",
        "High CVSS on a low-criticality, network-isolated printer usually schedules under standard change, not emergency IR.",
        "p3_schedule",
        "schedule_patch",
        {
            "high_cvss": True,
            "public_exploit": False,
            "critical_or_internet": False,
            "internal_only_low": False,
        },
    ),
    _case(
        "vpn_ssl_medium_edge",
        "VPN appliance SSL VPN weak cipher",
        2,
        """
Finding: Weak TLS ciphers enabled on SSL VPN portal
CVSS: 6.5
Exploitability: Downgrade / known weak-suite tooling exists
Asset: VPN-EDGE-01 (internet-facing remote access). Criticality: HIGH
Owner: Network team; next maintenance window is 3 weeks out
""",
        "Medium CVSS on an internet VPN edge still deserves urgent planning (P2). Criticality and exposure beat waiting a month.",
        "p2_urgent",
        "patch_now_escalate",
        {
            "high_cvss": False,
            "public_exploit": True,
            "critical_or_internet": True,
            "internal_only_low": False,
        },
    ),
    _case(
        "info_banner_fp",
        "Info disclosure: server banner version only",
        2,
        """
Finding: HTTP Server header discloses nginx version
CVSS: 5.3 (informational / low impact)
Exploitability: Version leak alone; no confirmed vuln for that build in stub
Asset: www-marketing (public brochure site). Criticality: LOW
Owner note: Accept risk until next content deploy; WAF in front
""",
        "Banner/version leak on a low-impact site is often accept or schedule hygiene, not a P1 fire drill.",
        "p4_accept_or_fp",
        "accept_or_fp",
        {
            "high_cvss": False,
            "public_exploit": False,
            "critical_or_internet": False,
            "internal_only_low": True,
        },
    ),
]

PRIORITIES = [
    {
        "id": "p1_immediate",
        "label": "P1 — Immediate (contain / patch now)",
        "why": "Internet-facing or wormable + high impact.",
    },
    {
        "id": "p2_urgent",
        "label": "P2 — Urgent (this week, critical asset)",
        "why": "Critical asset or known exploit path even if CVSS is medium.",
    },
    {
        "id": "p3_schedule",
        "label": "P3 — Schedule in normal patch cycle",
        "why": "Meaningful finding but needs user interaction / non-critical asset.",
    },
    {
        "id": "p4_accept_or_fp",
        "label": "P4 — Accept risk / false positive with owner",
        "why": "Expected lab noise or compensating controls + owner acknowledgment.",
    },
]

DISPOSITIONS = [
    {
        "id": "patch_now_escalate",
        "label": "Escalate for immediate patch / isolation",
        "why": "Exploitability + asset risk demand fast action.",
    },
    {
        "id": "schedule_patch",
        "label": "Open ticket for scheduled patch",
        "why": "Real finding, normal change window.",
    },
    {
        "id": "accept_or_fp",
        "label": "Mark accept / FP with asset owner note",
        "why": "Not production exposure or expected config.",
    },
    {
        "id": "ignore_cvss_only",
        "label": "Ignore because CVSS is not 10.0",
        "why": "Wrong: never use the number alone without asset and exploit context.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "high_cvss",
        "label": "Finding lists a high CVSS (roughly 7.0+) or equivalent critical label",
    },
    {
        "id": "public_exploit",
        "label": "Finding mentions public exploit / known attack path / wormable tooling",
    },
    {
        "id": "critical_or_internet",
        "label": "Asset is critical (e.g. DC) and/or internet-facing",
    },
    {
        "id": "internal_only_low",
        "label": "Exposure is localhost / lab-only on a low-criticality asset",
    },
]


def case_ids() -> list[str]:
    """Ordered case ids for next-scenario rotation."""
    return [c["id"] for c in CASES]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards without answer keys."""
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
    """Return one vuln triage case (canonical, no variants)."""
    for c in CASES:
        if c["id"] == case_id:
            return c
    return None


def materialize_case(case_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new asset names / hosts in the finding text."""
    case = get_case(case_id)
    if not case:
        return None
    return career_instances.materialize_generic(
        case,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["finding", "teach"],
        allow_ip=True,
    )


def next_after(case_id: str) -> dict[str, str]:
    """Random different case + fresh seed under /career/vuln."""
    return career_instances.next_scenario(case_ids(), case_id, "/career/vuln")


def grade_vuln(
    case_id: str,
    priority_id: str,
    disposition: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    """Grade priority + disposition + checklist."""
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
    pri_ok = (priority_id or "").strip() == case["correct_priority"]
    disp_ok = (disposition or "").strip() == case["correct_disposition"]
    # Checklist 4 + priority 2 + disposition 2
    score = hit + (2 if pri_ok else 0) + (2 if disp_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    pri_meta = next((p for p in PRIORITIES if p["id"] == case["correct_priority"]), None)
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == case["correct_disposition"]), None
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "priority_correct": pri_ok,
        "correct_priority": case["correct_priority"],
        "disposition_correct": disp_ok,
        "correct_disposition": case["correct_disposition"],
        "teach": case["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="priority",
                label=(pri_meta or {}).get("label") or case["correct_priority"],
                matched=pri_ok,
                rationale=(
                    f"Why this priority: {(pri_meta or {}).get('why') or ''} "
                    f"For this case: {case['teach']}"
                ).strip(),
                title="Why this priority",
                row_label="Correct priority",
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
