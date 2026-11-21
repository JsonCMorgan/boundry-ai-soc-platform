"""
Tune-or-tolerate drills (G17) — after FP-heavy patterns.

Choices: tune (narrow the rule), tolerate (accept with reason), escalate to detection owner.
"""

from __future__ import annotations

from typing import Any

import career_rationale

TRACK_TITLE = "Tune or Tolerate"
TRACK_BLURB = (
    "After noisy false positives, pick the right next step: tune the detection, "
    "tolerate with a written reason, or escalate to the detection owner. Not every FP is a tune."
)

PRIMER = [
    {
        "term": "Tune",
        "plain": "Change the detection so the same expected activity stops alerting (scoped, not blind).",
    },
    {
        "term": "Tolerate",
        "plain": "Keep the rule as-is. Document why this hit is acceptable noise for now.",
    },
    {
        "term": "Detection owner",
        "plain": "The person or team who owns the rule logic. Escalate when the fix needs design, not a quick allowlist.",
    },
]

DRILLS: list[dict[str, Any]] = [
    {
        "id": "tn_scanner",
        "title": "Nessus scanner from approved IP",
        "difficulty": "easy",
        "story": (
            "Rule 'Suspicious port scan' fires daily when approved scanner 10.9.9.20 runs the Contoso "
            "vulnerability window. Every ticket closes FP. Business wants the scan to continue."
        ),
        "correct": "tune",
        "options": [
            {"id": "tune", "label": "Tune — allowlist scanner IP + scan window in the rule"},
            {"id": "tolerate", "label": "Tolerate — leave rule alone, close FP forever"},
            {"id": "escalate", "label": "Escalate — rebuild entire SIEM"},
        ],
        "teach": "Repeatable approved scanner noise is a scoped tune, not eternal manual FP closes.",
    },
    {
        "id": "tn_rare_travel",
        "title": "One VIP travel alert",
        "difficulty": "medium",
        "story": (
            "Impossible-travel alert for one NorthPeak exec who flew Toronto→London once this quarter. "
            "MFA success, HR travel note matches. Rule rarely fires."
        ),
        "correct": "tolerate",
        "options": [
            {"id": "tune", "label": "Tune — disable all travel alerts globally"},
            {"id": "tolerate", "label": "Tolerate — close FP with travel note; keep rule"},
            {"id": "escalate", "label": "Escalate — delete the user account"},
        ],
        "teach": "Rare, explained travel is tolerate + document. Do not gut the detection.",
    },
    {
        "id": "tn_mac_noise",
        "title": "Mac EDR 'unsigned binary' flood",
        "difficulty": "hard",
        "story": (
            "Harbor design Macs flood 'unsigned binary' alerts after a creative suite update. "
            "Hundreds per hour. Allowlisting one hash is not enough. Detection logic looks broken for Macs."
        ),
        "correct": "escalate",
        "options": [
            {"id": "tune", "label": "Tune — suppress all Mac alerts forever in one click"},
            {"id": "tolerate", "label": "Tolerate — manually close 400 tickets each day"},
            {"id": "escalate", "label": "Escalate — detection owner to redesign Mac coverage"},
        ],
        "teach": "Volume + broken logic needs the detection owner. Blind suppress is not a tune.",
    },
    {
        "id": "tn_svc_account",
        "title": "Service account 4625 burst",
        "difficulty": "medium",
        "story": (
            "Contoso svc_backup fails password every night at 01:00 after a rotation. "
            "Same account, same host, same window. Ops will fix the secret tomorrow."
        ),
        "correct": "tolerate",
        "options": [
            {"id": "tune", "label": "Tune — exclude all service accounts from 4625 forever"},
            {"id": "tolerate", "label": "Tolerate tonight with ticket to Ops; revisit if repeats after fix"},
            {"id": "escalate", "label": "Escalate — declare breach"},
        ],
        "teach": "Short-lived known misconfig: tolerate with an Ops ticket. Broad exclude is dangerous.",
    },
    {
        "id": "tn_proxy_cdn",
        "title": "Proxy 'newly registered' on corporate CDN",
        "difficulty": "medium",
        "story": (
            "Contoso proxy rule flags every fetch to assets.contoso-cdn.lab as newly_registered. "
            "Marketing owns that CDN. Hundreds of FPs per deploy. Domain is on the allowlist request."
        ),
        "correct": "tune",
        "options": [
            {"id": "tune", "label": "Tune — allowlist the corporate CDN domain in the newly-registered rule"},
            {"id": "tolerate", "label": "Tolerate — close every marketing deploy as FP forever"},
            {"id": "escalate", "label": "Escalate — shut down the CDN"},
        ],
        "teach": "Owned business infrastructure that repeatedly trips a generic rule is a scoped tune.",
    },
    {
        "id": "tn_mfa_flood",
        "title": "MFA fatigue alerts after IdP outage",
        "difficulty": "hard",
        "story": (
            "After a NorthPeak IdP outage, every user re-prompts MFA and the 'MFA fatigue' rule "
            "fires for hundreds of accounts in one hour. Pattern matches the outage window only."
        ),
        "correct": "tolerate",
        "options": [
            {"id": "tune", "label": "Tune — disable MFA fatigue detection for 90 days"},
            {"id": "tolerate", "label": "Tolerate this outage window with a bulk note; keep the rule"},
            {"id": "escalate", "label": "Escalate — force password reset for every tenant user"},
        ],
        "teach": "One-time outage storms are tolerate + bulk document. Do not disable the detection for months.",
    },
]


def list_drills() -> list[dict[str, Any]]:
    """Hub cards."""
    return [
        {
            "id": d["id"],
            "title": d["title"],
            "difficulty": d["difficulty"],
        }
        for d in DRILLS
    ]


def get_drill(drill_id: str) -> dict[str, Any] | None:
    """Public drill without correct answer."""
    for d in DRILLS:
        if d["id"] == drill_id:
            return {
                "id": d["id"],
                "title": d["title"],
                "difficulty": d["difficulty"],
                "story": d["story"],
                "options": d["options"],
                "teach": d["teach"],
            }
    return None


def grade_tune(drill_id: str, choice: str) -> dict[str, Any]:
    """Grade tune/tolerate/escalate choice."""
    d = next((x for x in DRILLS if x["id"] == drill_id), None)
    if not d:
        return {"ok": False, "error": "Unknown drill"}
    choice = (choice or "").strip().lower()
    if choice not in ("tune", "tolerate", "escalate"):
        return {"ok": False, "error": "Pick tune, tolerate, or escalate."}
    passed = choice == d["correct"]
    pct = 100 if passed else 35
    tip = (
        "Correct. " + d["teach"]
        if passed
        else f"Common trap. Right answer was {d['correct']}. {d['teach']}"
    )
    opt_label = next(
        (o["label"] for o in d["options"] if o["id"] == d["correct"]),
        d["correct"],
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": passed,
        "tips": [tip],
        "teach": d["teach"],
        "correct": d["correct"],
        "answer_chips": [
            career_rationale.chip(
                id="choice",
                label=opt_label,
                matched=passed,
                rationale=d["teach"],
                title="Why tune / tolerate / escalate",
                row_label="Correct choice",
            ),
        ],
    }
