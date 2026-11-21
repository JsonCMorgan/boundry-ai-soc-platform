"""
Automation policy per Practice tenant (G22) — owner-era human gates.

Clients: Contoso, NorthPeak, Harbor. Modes for enrich and contain.
"""

from __future__ import annotations

from typing import Any

import career_rationale

TRACK_TITLE = "Automation Policy"
TRACK_BLURB = (
    "Decide, per Practice client, what automation may do alone versus what needs a human. "
    "This is the MSSP owner skill clients trust when they ask about audit."
)

PRIMER = [
    {
        "term": "Auto-enrich",
        "plain": "Lookups and ticket fields can run without waiting for you.",
    },
    {
        "term": "Approve-contain",
        "plain": "Containment (block, isolate, revoke) is proposed, then a human must approve.",
    },
    {
        "term": "Never auto",
        "plain": "No automated enrich or contain for that action class. Human does it manually.",
    },
]

CLIENTS = ["Contoso", "NorthPeak", "Harbor"]

# Suggested baseline policies used for grading "set policy" drill
BASELINE: dict[str, dict[str, str]] = {
    "Contoso": {"enrich": "auto", "contain": "approve"},
    "NorthPeak": {"enrich": "approve", "contain": "approve"},
    "Harbor": {"enrich": "auto", "contain": "never"},
}

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "pl_set_baseline",
        "title": "Set baseline policies for three Practice clients",
        "difficulty": "medium",
        "kind": "set_policy",
        "brief": (
            "Contoso: mature, allow auto-enrich, contain needs approve. "
            "NorthPeak: VIP-heavy, enrich and contain both need approve. "
            "Harbor: OT-adjacent warehouse, auto-enrich OK, never auto-contain."
        ),
        "teach": "Policy is per tenant. VIP and OT-adjacent clients get tighter gates.",
    },
    {
        "id": "pl_apply_harbor",
        "title": "Harbor isolate proposal — what does policy say?",
        "difficulty": "easy",
        "kind": "apply",
        "story": (
            "Playbook proposes EDR isolate on Harbor WH-PC07. Harbor policy is enrich=auto, contain=never."
        ),
        "correct": "manual_contain",
        "choices": [
            {"id": "auto_run", "label": "Let SOAR isolate immediately"},
            {"id": "approve_gate", "label": "Show approve button (approve-contain)"},
            {"id": "manual_contain", "label": "Never auto — analyst contains manually if needed"},
        ],
        "teach": "Harbor never auto-contain. Propose is not enough; humans act outside the auto path.",
    },
    {
        "id": "pl_apply_contoso",
        "title": "Contoso spray enrich — what does policy say?",
        "difficulty": "easy",
        "kind": "apply",
        "story": (
            "Contoso spray alert needs IP reputation. Contoso policy enrich=auto, contain=approve."
        ),
        "correct": "auto_enrich",
        "choices": [
            {"id": "auto_enrich", "label": "Auto-enrich the IP, then wait for human on any block"},
            {"id": "block_now", "label": "Auto-block the IP with no human"},
            {"id": "never", "label": "Do nothing until the client emails"},
        ],
        "teach": "Auto-enrich is fine for Contoso. Contain still waits on approve.",
    },
]


def list_scenarios() -> list[dict[str, Any]]:
    """Hub cards."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "difficulty": s["difficulty"],
            "kind": s["kind"],
        }
        for s in SCENARIOS
    ]


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    """Public scenario."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            out = {
                "id": s["id"],
                "title": s["title"],
                "difficulty": s["difficulty"],
                "kind": s["kind"],
                "teach": s["teach"],
                "clients": CLIENTS,
                "modes_enrich": ["auto", "approve", "never"],
                "modes_contain": ["approve", "never"],
            }
            if s["kind"] == "set_policy":
                out["brief"] = s["brief"]
            else:
                out["story"] = s["story"]
                out["choices"] = s["choices"]
            return out
    return None


def grade_policy(scenario_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Grade set_policy or apply drills."""
    s = next((x for x in SCENARIOS if x["id"] == scenario_id), None)
    if not s:
        return {"ok": False, "error": "Unknown scenario"}

    if s["kind"] == "set_policy":
        policies = payload.get("policies") or {}
        if not isinstance(policies, dict):
            return {"ok": False, "error": "Need policies map"}
        hits = 0
        tips: list[str] = []
        for client, want in BASELINE.items():
            got = policies.get(client) or {}
            ok_e = (got.get("enrich") or "").lower() == want["enrich"]
            ok_c = (got.get("contain") or "").lower() == want["contain"]
            if ok_e and ok_c:
                hits += 1
            else:
                tips.append(
                    f"{client}: expected enrich={want['enrich']}, contain={want['contain']}"
                )
        pct = round(100 * hits / max(len(BASELINE), 1))
        if not tips:
            tips.append("Baseline matches the brief. Save these for Practice tenants.")
        return {
            "ok": True,
            "pct": pct,
            "passed": pct >= 70,
            "tips": tips,
            "teach": s["teach"],
            "baseline": BASELINE,
            "answer_chips": [
                career_rationale.chip(
                    id="baseline",
                    label="Per-tenant enrich/contain baseline",
                    matched=pct >= 70,
                    rationale=s["teach"] + " Contoso auto-enrich/approve-contain; "
                    "NorthPeak approve both; Harbor auto-enrich/never-contain.",
                    title="Why this policy set",
                    row_label="Correct baseline shape",
                ),
            ],
        }

    choice = (payload.get("choice") or "").strip()
    passed = choice == s["correct"]
    opt_label = next(
        (c["label"] for c in s.get("choices") or [] if c["id"] == s["correct"]),
        s["correct"],
    )
    return {
        "ok": True,
        "pct": 100 if passed else 30,
        "passed": passed,
        "tips": [s["teach"] if passed else f"Miss. {s['teach']}"],
        "teach": s["teach"],
        "correct": s["correct"],
        "answer_chips": [
            career_rationale.chip(
                id="choice",
                label=opt_label,
                matched=passed,
                rationale=s["teach"],
                title="Why this policy application",
                row_label="Correct application",
            ),
        ],
    }
