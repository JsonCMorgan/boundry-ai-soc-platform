"""
Autopilot Oversight Gym (G21) — validate or override stub agent verdicts.

Local stubs only. Agent is intentionally wrong on some cases.
"""

from __future__ import annotations

from typing import Any

import career_rationale

TRACK_TITLE = "Autopilot Oversight Gym"
TRACK_BLURB = (
    "Practice the human job after automation: read the agent verdict, check evidence, "
    "agree or override. Some stub agents are wrong on purpose. No cloud ops AI."
)

PRIMER = [
    {
        "term": "Agent verdict",
        "plain": "An automated triage suggestion (true positive, false positive, or escalate).",
    },
    {
        "term": "Override",
        "plain": "You disagree with the agent and pick a different disposition, with evidence.",
    },
    {
        "term": "Evidence cue",
        "plain": "The fact in the case that proves the agent right or wrong.",
    },
]

CASES: list[dict[str, Any]] = [
    {
        "id": "ao_fp_vpn",
        "title": "VPN admin login flagged as spray",
        "difficulty": "easy",
        "story": (
            "Agent says TRUE POSITIVE spray. Evidence: one Contoso admin, three failed then success "
            "from known corporate VPN 198.51.100.10, MFA satisfied, change ticket open."
        ),
        "agent_verdict": "true_positive",
        "agent_confidence": 0.82,
        "agent_rationale": "Multiple failures then success = spray.",
        "correct_action": "override_fp",
        "evidence_options": [
            {"id": "vpn_mfa", "label": "Known VPN + MFA success + change ticket"},
            {"id": "many_users", "label": "Many users hit from one IP"},
            {"id": "ransom", "label": "Ransom note on disk"},
        ],
        "correct_evidence": "vpn_mfa",
        "teach": "Spray needs breadth. One admin on VPN with MFA is often a fat-finger, not spray.",
    },
    {
        "id": "ao_tp_ransom",
        "title": "Harbor mass rename — agent says FP",
        "difficulty": "medium",
        "story": (
            "Agent says FALSE POSITIVE. Evidence: WH-PC07 created HOW_TO_DECRYPT.txt and renamed "
            "400 files in 6 minutes. No backup job scheduled."
        ),
        "agent_verdict": "false_positive",
        "agent_confidence": 0.71,
        "agent_rationale": "File renames can be backup tools.",
        "correct_action": "override_tp",
        "evidence_options": [
            {"id": "note_mass", "label": "Ransom note filename + mass renames"},
            {"id": "backup", "label": "Scheduled backup job matches the window"},
            {"id": "vpn", "label": "User on corporate VPN only"},
        ],
        "correct_evidence": "note_mass",
        "teach": "Mass rename + decrypt note is classic ransomware. Override the FP agent.",
    },
    {
        "id": "ao_agree_bec",
        "title": "NorthPeak forward rule — agent TP",
        "difficulty": "easy",
        "story": (
            "Agent says TRUE POSITIVE BEC. Evidence: external forward on CFO mailbox to unknown domain, "
            "created at 02:11 local, no travel, MFA prompt fatigue earlier that night."
        ),
        "agent_verdict": "true_positive",
        "agent_confidence": 0.88,
        "agent_rationale": "External forward + odd hour + MFA fatigue.",
        "correct_action": "agree",
        "evidence_options": [
            {"id": "forward", "label": "External forward + MFA fatigue + odd hour"},
            {"id": "newsletter", "label": "Marketing newsletter open"},
            {"id": "patch", "label": "VPN patch window"},
        ],
        "correct_evidence": "forward",
        "teach": "When the agent cites the right persistence cue, agree and document.",
    },
    {
        "id": "ao_escalate",
        "title": "Ambiguous lateral — agent closes FP",
        "difficulty": "hard",
        "story": (
            "Agent says FALSE POSITIVE. Evidence: new local admin on FILE-02, then RDP to FIN-PC09. "
            "No change ticket. EDR has no malware verdict yet."
        ),
        "agent_verdict": "false_positive",
        "agent_confidence": 0.64,
        "agent_rationale": "No malware hash hit.",
        "correct_action": "override_escalate",
        "evidence_options": [
            {"id": "admin_rdp", "label": "New local admin + RDP without change ticket"},
            {"id": "hash_clean", "label": "No malware hash means safe"},
            {"id": "lunch", "label": "Happened during lunch"},
        ],
        "correct_evidence": "admin_rdp",
        "teach": "Missing malware hash is not a close. Privilege + lateral without ticket → escalate.",
    },
    {
        "id": "ao_fp_patch",
        "title": "Patch window PowerShell — agent TP",
        "difficulty": "easy",
        "story": (
            "Agent says TRUE POSITIVE malware. Evidence: SCCM parent, quiet msiexec from CCM Cache, "
            "change window CHG-9901, no network beacon."
        ),
        "agent_verdict": "true_positive",
        "agent_confidence": 0.79,
        "agent_rationale": "PowerShell and msiexec mean malware.",
        "correct_action": "override_fp",
        "evidence_options": [
            {"id": "sccm_chg", "label": "SCCM parent + CCM Cache MSI + change ticket"},
            {"id": "c2", "label": "Encoded PowerShell downloaded from rare IP"},
            {"id": "ransom", "label": "Ransom note on desktop"},
        ],
        "correct_evidence": "sccm_chg",
        "teach": "Known management agent in a change window is FP. Override the agent.",
    },
    {
        "id": "ao_tp_mfa",
        "title": "MFA fatigue success — agent FP",
        "difficulty": "medium",
        "story": (
            "Agent says FALSE POSITIVE. Evidence: 14 MFA pushes overnight, one approved, "
            "rare geo session still active, user says they did not approve."
        ),
        "agent_verdict": "false_positive",
        "agent_confidence": 0.70,
        "agent_rationale": "MFA succeeded so the session is legitimate.",
        "correct_action": "override_tp",
        "evidence_options": [
            {"id": "fatigue", "label": "Push flood + user denial + rare geo session"},
            {"id": "travel", "label": "HR travel note matches the geo"},
            {"id": "newsletter", "label": "User opened a newsletter"},
        ],
        "correct_evidence": "fatigue",
        "teach": "MFA success under fatigue is still a true positive identity incident.",
    },
]

ACTIONS = [
    {"id": "agree", "label": "Agree with agent"},
    {"id": "override_fp", "label": "Override → false positive"},
    {"id": "override_tp", "label": "Override → true positive"},
    {"id": "override_escalate", "label": "Override → escalate"},
]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards."""
    return [
        {
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "agent_verdict": c["agent_verdict"],
        }
        for c in CASES
    ]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Public case payload (no correct answers)."""
    for c in CASES:
        if c["id"] == case_id:
            return {
                "id": c["id"],
                "title": c["title"],
                "difficulty": c["difficulty"],
                "story": c["story"],
                "agent_verdict": c["agent_verdict"],
                "agent_confidence": c["agent_confidence"],
                "agent_rationale": c["agent_rationale"],
                "evidence_options": c["evidence_options"],
                "actions": ACTIONS,
                "teach": c["teach"],
            }
    return None


def grade_oversight(case_id: str, action: str, evidence_id: str) -> dict[str, Any]:
    """Grade agree/override + evidence pick."""
    c = next((x for x in CASES if x["id"] == case_id), None)
    if not c:
        return {"ok": False, "error": "Unknown case"}
    act = (action or "").strip()
    ev = (evidence_id or "").strip()
    tips: list[str] = []
    pct = 0
    if act == c["correct_action"]:
        pct += 60
    else:
        tips.append(f"Correct action was {c['correct_action'].replace('_', ' ')}.")
    if ev == c["correct_evidence"]:
        pct += 40
    else:
        tips.append("Evidence cue did not match the deciding fact.")
    pct = max(0, min(100, pct))
    passed = pct >= 70
    if not tips:
        tips.append("Good oversight. You checked the agent against evidence.")
    act_label = next(
        (a["label"] for a in ACTIONS if a["id"] == c["correct_action"]),
        c["correct_action"],
    )
    ev_label = next(
        (e["label"] for e in c["evidence_options"] if e["id"] == c["correct_evidence"]),
        c["correct_evidence"],
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": passed,
        "tips": tips,
        "teach": c["teach"],
        "correct_action": c["correct_action"],
        "correct_evidence": c["correct_evidence"],
        "answer_chips": [
            career_rationale.chip(
                id="action",
                label=act_label,
                matched=act == c["correct_action"],
                rationale=c["teach"],
                title="Why this oversight action",
                row_label="Correct action",
            ),
            career_rationale.chip(
                id="evidence",
                label=ev_label,
                matched=ev == c["correct_evidence"],
                rationale=f"This cue is the deciding fact. {c['teach']}",
                title="Why this evidence cue",
                row_label="Correct evidence",
            ),
        ],
    }
