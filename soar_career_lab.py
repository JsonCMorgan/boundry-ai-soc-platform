"""
SOAR Career prove-it (G13) — enrich → propose → approve/deny → ticket note.

Practice-only multi-step playbook chain. Live /soar stays separate for real findings.
"""

from __future__ import annotations

from typing import Any

import career_rationale
import ticket_fields

TRACK_TITLE = "SOAR Chain Lab"
TRACK_BLURB = (
    "Walk a multi-step playbook the way 2026 desks expect: enrich first, propose containment, "
    "human approve or deny with a reason, then write the ticket note. Local practice only."
)

# Hub one-liner: desk habit vs Sec+ definitions
LEARN_NOTE = (
    "This lab trains the human-gate habit for the desk (enrich → propose → approve/deny → ticket). "
    "CompTIA Security+ definitions for automation and SOAR live in Domain 4 Show-me: "
    "Automation and SOAR with a human gate."
)

SECPLUS_LESSON_HREF = "/career/secplus/lesson/sp_d4_10_automation_soar"

PRIMER = [
    {
        "term": "Enrich",
        "plain": "Look up an indicator (IP, domain, hash) and write what you found before you contain.",
    },
    {
        "term": "Propose",
        "plain": "Automation suggests a containment action. It is not done until a human gates it.",
    },
    {
        "term": "Human gate",
        "plain": "You approve or deny the proposed action and record why. That is the audit story.",
    },
    {
        "term": "Ticket fields",
        "plain": (
            "Fill each ITSM-style field: client, priority, disposition, what happened, "
            "evidence, actions taken, and next action. Do not dump one freeform blob."
        ),
    },
]

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "sc_spray_block",
        "title": "Contoso password spray — block source IP",
        "client": "Contoso",
        "difficulty": "easy",
        "alert": (
            "45 failed logons for 12 Contoso users from 203.0.113.44 in 8 minutes. "
            "No successful logon yet. Playbook proposes firewall block on that IP."
        ),
        "ioc": "203.0.113.44",
        "enrich_stub": {
            "reputation": "suspicious",
            "note": "Local stub: IP seen in spray patterns; no business allowlist hit.",
        },
        "enrich_coach": (
            "Reputation here means a local practice score for the IP, not a live cloud lookup. "
            "Suspicious plus many users failing from one source with no success yet is a classic "
            "password spray pattern. A short edge block is a reasonable contain while you keep watching."
        ),
        "look_for": [
            "Many users, one source IP (spray breadth)",
            "No successful logon yet",
            "No business allowlist hit on the IP",
        ],
        "reason_scaffold": (
            "Approve short block: spray from [IP] against [N] Contoso users, "
            "no success yet, enrich shows [reputation], not on allowlist."
        ),
        "ticket_scaffold": (
            "Contoso: enriched [IOC] ([reputation]). Approved 24h edge block. "
            "Reason: spray pattern, no success. Monitoring for successful logons."
        ),
        "ticket_seed": {
            "client": "Contoso",
            "priority": "p2",
            "disposition": "escalate",
            "evidence": "IOC 203.0.113.44 — enrich reputation suspicious; no allowlist hit.",
        },
        "ticket_expected": {
            "client": {"value": "Contoso", "why": "Alert is Contoso tenants only."},
            "priority": {"value": "p2", "why": "Active spray with no success yet needs urgent contain."},
            "disposition": {
                "values": ["escalate", "true_positive"],
                "why": "Approve contain means true positive / escalate path, not FP close.",
            },
            "what_happened": {
                "must_include": ["spray", "fail"],
                "min_hits": 1,
                "min_len": 12,
                "why": "Name the password-spray pattern.",
            },
            "evidence": {
                "must_include": ["203.0.113.44", "suspicious", "enrich"],
                "min_hits": 2,
                "min_len": 12,
                "why": "Cite the IOC and enrich result.",
            },
            "actions_taken": {
                "must_include": ["approv", "block"],
                "min_hits": 2,
                "min_len": 10,
                "why": "Record that you approved the edge block.",
            },
            "next_action": {
                "must_include": ["monitor", "success"],
                "min_hits": 1,
                "min_len": 10,
                "why": "Say what you watch for next (successful logons).",
            },
        },
        "proposed_action": "Block 203.0.113.44 at edge firewall for 24h",
        "correct_decision": "approve",
        "decision_reason_keys": ["spray", "no success", "block"],
        "wrong_if_deny_hint": "Denying leaves the spray source active with no compensating control.",
        "ticket_must": ["enriched", "approved", "block", "contoso"],
        "teach": "Enrich confirms spray pattern. Approve short block. Ticket must show enrich + gate.",
    },
    {
        "id": "sc_admin_jump",
        "title": "Harbor jump-box — deny reckless isolate",
        "client": "Harbor",
        "difficulty": "medium",
        "alert": (
            "Harbor jump-host JUMP-01 shows one PowerShell 4104 event during a change window. "
            "Playbook proposes full host isolate. Change ticket CHG-4412 is open for that host."
        ),
        "ioc": "JUMP-01",
        "enrich_stub": {
            "reputation": "benign_context",
            "note": "Local stub: host is PAM jump box; CHG-4412 approved PowerShell runbook.",
        },
        "enrich_coach": (
            "Benign context means the stub found a business explanation, not malware proof. "
            "A PAM jump box is an admin stepping-stone host. Isolating it mid-change can cut "
            "legitimate admin paths. Deny contain when the change ticket matches the signal."
        ),
        "look_for": [
            "Open change ticket CHG-4412",
            "Host is a PAM jump box",
            "Single PowerShell event, not a malware chain",
        ],
        "reason_scaffold": (
            "Deny isolate: JUMP-01 is Harbor PAM jump box; CHG-[id] covers PowerShell runbook "
            "in this window. Enrich = benign_context. No malware chain."
        ),
        "ticket_scaffold": (
            "Harbor: enriched JUMP-01 (benign_context). Denied EDR isolate. "
            "Reason: change ticket + jump-box context. Watching for non-change activity."
        ),
        "ticket_seed": {
            "client": "Harbor",
            "priority": "p3",
            "disposition": "monitor",
            "evidence": "IOC JUMP-01 — enrich benign_context; CHG-4412 open.",
        },
        "ticket_expected": {
            "client": {"value": "Harbor", "why": "Jump host belongs to Harbor."},
            "priority": {"value": "p3", "why": "Change-window context is standard, not P1 ransomware."},
            "disposition": {
                "values": ["false_positive", "monitor"],
                "why": "Deny isolate: close as FP or monitor for non-change activity.",
            },
            "what_happened": {
                "must_include": ["powershell", "change", "jump"],
                "min_hits": 2,
                "min_len": 12,
            },
            "evidence": {
                "must_include": ["jump-01", "change", "benign"],
                "min_hits": 2,
                "min_len": 12,
            },
            "actions_taken": {
                "must_include": ["deni", "isolate"],
                "min_hits": 2,
                "min_len": 10,
            },
            "next_action": {
                "must_include": ["watch", "monitor", "change"],
                "min_hits": 1,
                "min_len": 10,
            },
        },
        "proposed_action": "Isolate JUMP-01 via EDR",
        "correct_decision": "deny",
        "decision_reason_keys": ["change", "jump", "deny"],
        "wrong_if_approve_hint": (
            "Isolating a jump box mid-change can break admin paths without strong malware evidence."
        ),
        "ticket_must": ["enriched", "denied", "change", "harbor"],
        "teach": "Context beats autopilot. Deny isolate when change evidence explains the signal.",
    },
    {
        "id": "sc_bec_revoke",
        "title": "NorthPeak BEC — approve session revoke",
        "client": "NorthPeak",
        "difficulty": "medium",
        "alert": (
            "NorthPeak CFO mailbox: new external forward rule to finance-pay.example. "
            "Playbook proposes revoke sessions + remove rule. No ransom note on endpoints."
        ),
        "ioc": "finance-pay.example",
        "enrich_stub": {
            "reputation": "malicious",
            "note": "Local stub: domain young, no NorthPeak business relationship.",
        },
        "enrich_coach": (
            "Malicious here means the stub treats the forward domain as hostile practice intel. "
            "BEC means business email compromise: attackers abuse mail and money paths. "
            "An external forward rule is persistence. Approve removing the rule and revoking sessions."
        ),
        "look_for": [
            "External forward to unknown domain",
            "Domain has no client business relationship",
            "Containment is revoke sessions + remove rule (not endpoint ransomware)",
        ],
        "reason_scaffold": (
            "Approve revoke: NorthPeak CFO external forward to [domain], enrich malicious, "
            "no business relationship. Remove rule + revoke sessions (BEC persistence)."
        ),
        "ticket_scaffold": (
            "NorthPeak: enriched finance-pay.example (malicious). Approved remove forward + "
            "session revoke. Reason: BEC-style persistence. Finance callback reminder sent."
        ),
        "ticket_seed": {
            "client": "NorthPeak",
            "priority": "p2",
            "disposition": "escalate",
            "evidence": "IOC finance-pay.example — enrich malicious; no business relationship.",
        },
        "ticket_expected": {
            "client": {"value": "NorthPeak", "why": "CFO mailbox is NorthPeak."},
            "priority": {"value": "p2", "why": "Active BEC persistence needs urgent contain."},
            "disposition": {
                "values": ["escalate", "true_positive"],
                "why": "Approve revoke is a true-positive / escalate path.",
            },
            "what_happened": {
                "must_include": ["forward", "bec", "cfo"],
                "min_hits": 1,
                "min_len": 12,
            },
            "evidence": {
                "must_include": ["finance-pay", "malicious", "enrich"],
                "min_hits": 2,
                "min_len": 12,
            },
            "actions_taken": {
                "must_include": ["approv", "revoke", "forward"],
                "min_hits": 2,
                "min_len": 10,
            },
            "next_action": {
                "must_include": ["finance", "callback", "confirm"],
                "min_hits": 1,
                "min_len": 10,
            },
        },
        "proposed_action": "Remove forward rule and revoke active sessions on CFO account",
        "correct_decision": "approve",
        "decision_reason_keys": ["forward", "revoke", "bec"],
        "wrong_if_deny_hint": "Leaving the forward up continues data exposure.",
        "ticket_must": ["enriched", "approved", "forward", "northpeak"],
        "teach": "BEC persistence is the rule + sessions. Approve contain that removes both.",
    },
    {
        "id": "sc_ransom_isolate",
        "title": "Harbor ransomware — approve isolate",
        "client": "Harbor",
        "difficulty": "easy",
        "alert": (
            "Harbor WH-PC07: HOW_TO_DECRYPT.txt + 400 file renames in 6 minutes. "
            "Playbook proposes EDR isolate. No backup job matches the window."
        ),
        "ioc": "WH-PC07",
        "enrich_stub": {
            "reputation": "malicious",
            "note": "Local stub: ransom note filename + mass rename pattern.",
        },
        "enrich_coach": (
            "Malicious matches ransomware behavior: a decrypt note filename plus mass renames. "
            "EDR isolate means cutting the host off the network so encryption cannot keep spreading. "
            "Approve quickly. Waiting for a clean file hash is the common trap."
        ),
        "look_for": [
            "Ransom-note style filename",
            "Mass renames in a short window",
            "No matching backup job explanation",
        ],
        "reason_scaffold": (
            "Approve isolate WH-PC07: ransom note filename + mass renames, enrich malicious, "
            "no backup job in window. Contain first."
        ),
        "ticket_scaffold": (
            "Harbor: enriched WH-PC07 (malicious). Approved EDR isolate. "
            "Reason: ransomware indicators (note + renames). Escalating IR; no restore started."
        ),
        "ticket_seed": {
            "client": "Harbor",
            "priority": "p1",
            "disposition": "escalate",
            "evidence": "IOC WH-PC07 — enrich malicious; ransom note + mass renames.",
        },
        "ticket_expected": {
            "client": {"value": "Harbor", "why": "Host WH-PC07 is Harbor."},
            "priority": {"value": "p1", "why": "Active ransomware encryption is immediate."},
            "disposition": {
                "values": ["escalate", "true_positive"],
                "why": "Approve isolate and escalate IR.",
            },
            "what_happened": {
                "must_include": ["ransom", "rename", "encrypt"],
                "min_hits": 1,
                "min_len": 12,
            },
            "evidence": {
                "must_include": ["wh-pc07", "malicious", "ransom"],
                "min_hits": 2,
                "min_len": 12,
            },
            "actions_taken": {
                "must_include": ["approv", "isolate"],
                "min_hits": 2,
                "min_len": 10,
            },
            "next_action": {
                "must_include": ["ir", "escalat", "restore"],
                "min_hits": 1,
                "min_len": 10,
            },
        },
        "proposed_action": "Isolate WH-PC07 via EDR",
        "correct_decision": "approve",
        "decision_reason_keys": ["ransom", "isolate", "rename"],
        "wrong_if_deny_hint": "Denying isolate lets encryption continue on a live host.",
        "ticket_must": ["enriched", "approved", "isolate", "harbor"],
        "teach": "Ransomware indicators justify immediate isolate. Approve and ticket the gate.",
    },
    {
        "id": "sc_shared_vpn_deny",
        "title": "Contoso shared VPN IP — deny global block",
        "client": "Contoso",
        "difficulty": "hard",
        "alert": (
            "One Contoso exec success from shared VPN exit 198.51.100.200. "
            "Playbook proposes block that IP at the edge for all tenants for 7 days."
        ),
        "ioc": "198.51.100.200",
        "enrich_stub": {
            "reputation": "suspicious",
            "note": "Local stub: shared VPN exit used by many orgs; one success only.",
        },
        "enrich_coach": (
            "Suspicious is not the same as proven attacker infrastructure. A shared VPN exit is an "
            "IP many travelers may use. One successful sign-in is thin evidence for a global "
            "7-day block. Deny the blunt firewall action; follow up on the identity instead."
        ),
        "look_for": [
            "Shared VPN exit (many orgs)",
            "Only one successful sign-in",
            "Proposed action is a long global block (high blast radius)",
        ],
        "reason_scaffold": (
            "Deny global block: [IP] is shared VPN exit, enrich suspicious only, "
            "one Contoso success. Prefer identity follow-up over 7-day tenant-wide block."
        ),
        "ticket_scaffold": (
            "Contoso: enriched 198.51.100.200 (suspicious, shared VPN). Denied global edge block. "
            "Reason: thin evidence / high blast radius. Next: session review with the exec."
        ),
        "ticket_seed": {
            "client": "Contoso",
            "priority": "p3",
            "disposition": "monitor",
            "evidence": "IOC 198.51.100.200 — enrich suspicious; shared VPN exit.",
        },
        "ticket_expected": {
            "client": {"value": "Contoso", "why": "Exec success is a Contoso identity."},
            "priority": {
                "value": "p3",
                "why": "Thin evidence for a blunt block; identity follow-up is standard priority.",
            },
            "disposition": {
                "values": ["monitor", "false_positive"],
                "why": "Deny global block: monitor / do not treat as confirmed compromise.",
            },
            "what_happened": {
                "must_include": ["vpn", "success", "shared"],
                "min_hits": 2,
                "min_len": 12,
            },
            "evidence": {
                "must_include": ["198.51.100.200", "vpn", "suspicious"],
                "min_hits": 2,
                "min_len": 12,
            },
            "actions_taken": {
                "must_include": ["deni", "block"],
                "min_hits": 2,
                "min_len": 10,
            },
            "next_action": {
                "must_include": ["session", "exec", "identity"],
                "min_hits": 1,
                "min_len": 10,
            },
        },
        "proposed_action": "Block 198.51.100.200 globally for 7 days",
        "correct_decision": "deny",
        "decision_reason_keys": ["shared", "vpn", "deny"],
        "wrong_if_approve_hint": (
            "Blocking a shared VPN exit can break travel access for many users without proving compromise."
        ),
        "ticket_must": ["enriched", "denied", "vpn", "contoso"],
        "teach": "Shared exits need identity follow-up, not a blunt global firewall block.",
    },
]


def list_scenarios() -> list[dict[str, Any]]:
    """Hub cards."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "client": s["client"],
            "difficulty": s["difficulty"],
        }
        for s in SCENARIOS
    ]


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    """Full scenario for case page (no correct_decision leaked)."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return {
                "id": s["id"],
                "title": s["title"],
                "client": s["client"],
                "difficulty": s["difficulty"],
                "alert": s["alert"],
                "ioc": s["ioc"],
                "enrich_stub": s["enrich_stub"],
                "enrich_coach": s["enrich_coach"],
                "look_for": list(s["look_for"]),
                "reason_scaffold": s["reason_scaffold"],
                "ticket_scaffold": s["ticket_scaffold"],
                "ticket_seed": dict(s.get("ticket_seed") or {}),
                "ticket_fields": ticket_fields.fields_for_ui(),
                "proposed_action": s["proposed_action"],
                "teach": s["teach"],
                "secplus_href": SECPLUS_LESSON_HREF,
            }
    return None


def grade_chain(
    scenario_id: str,
    *,
    enriched: bool,
    decision: str,
    reason: str,
    ticket_note: str = "",
    ticket_fields_submitted: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Grade enrich → decide → ticket field console (legacy ticket_note still accepted)."""
    sc = next((s for s in SCENARIOS if s["id"] == scenario_id), None)
    if not sc:
        return {"ok": False, "error": "Unknown scenario"}

    tips: list[str] = []
    pct = 0

    if enriched:
        pct += 25
    else:
        tips.append("Run enrich before you gate the action.")

    dec = (decision or "").strip().lower()
    if dec not in ("approve", "deny"):
        return {"ok": False, "error": "Choose approve or deny."}
    if dec == sc["correct_decision"]:
        pct += 35
    else:
        tips.append(
            sc.get("wrong_if_deny_hint")
            if dec == "deny"
            else sc.get("wrong_if_approve_hint")
            or "Wrong gate decision for this evidence."
        )

    reason_l = (reason or "").lower()
    reason_hits = [k for k in sc["decision_reason_keys"] if k in reason_l]
    if len(reason_hits) >= 1 and len((reason or "").strip()) >= 12:
        pct += 15
    else:
        tips.append("Reason must cite the case facts (spray, change window, forward, etc.).")

    submitted = ticket_fields_submitted
    if not submitted and (ticket_note or "").strip():
        # Legacy freeform: treat whole note as what_happened + evidence blob
        submitted = {
            "client": sc["client"],
            "priority": (sc.get("ticket_seed") or {}).get("priority") or "p2",
            "disposition": (sc.get("ticket_seed") or {}).get("disposition") or "",
            "what_happened": ticket_note,
            "evidence": ticket_note,
            "actions_taken": ticket_note,
            "next_action": ticket_note,
        }

    field_grade = ticket_fields.grade_ticket_fields(
        sc.get("ticket_expected") or {},
        submitted,
    )
    note_score = round(25 * (field_grade["pct"] / 100))
    pct += note_score
    composed = field_grade.get("composed_note") or (ticket_note or "").strip()
    if not field_grade.get("passed"):
        miss = [fr["id"] for fr in field_grade.get("field_results") or [] if not fr.get("correct")]
        if miss:
            tips.append("Ticket fields need work: " + ", ".join(miss[:5]))
        else:
            tips.append("Fill every ticket field with case facts.")

    pct = max(0, min(100, pct))
    fields_ok = bool(field_grade.get("passed"))
    passed = pct >= 70 and dec == sc["correct_decision"] and enriched and fields_ok
    if not tips:
        tips.append("Clean chain. Audit can see enrich → gate → ticket fields.")

    chips = [
        career_rationale.chip(
            id="decision",
            label=("Approve" if sc["correct_decision"] == "approve" else "Deny"),
            matched=dec == sc["correct_decision"] and enriched,
            rationale=sc["teach"],
            title="Why this human gate",
            row_label="Correct gate decision",
        ),
    ]
    chips.extend(field_grade.get("answer_chips") or [])

    return {
        "ok": True,
        "pct": pct,
        "passed": passed,
        "tips": tips,
        "teach": sc["teach"],
        "correct_decision": sc["correct_decision"],
        "model_note": composed or (
            f"Enriched {sc['ioc']} ({sc['enrich_stub']['reputation']}). "
            f"{'Approved' if sc['correct_decision'] == 'approve' else 'Denied'} "
            f"{sc['proposed_action']}. Reason logged. Client {sc['client']}."
        ),
        "field_results": field_grade.get("field_results") or [],
        "composed_note": composed,
        "answer_chips": chips,
    }
