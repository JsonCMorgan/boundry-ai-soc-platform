"""
Ops metrics literacy (G16) — Show-me + short quiz for owner-era KPIs.

No fake MDR claims. Explains MTTD, MTTR, FP rate for QBRs and self-ops.
"""

from __future__ import annotations

from typing import Any

import career_rationale

TRACK_TITLE = "Ops Metrics Literacy"
TRACK_BLURB = (
    "Learn the numbers managers ask about: how fast you detect, how fast you contain, "
    "and how noisy the queue is. Use them honestly. Boundry is not claiming 24x7 MDR here."
)

SHOW_ME = {
    "title": "What these metrics mean on a desk",
    "beats": [
        {
            "term": "MTTD",
            "plain": "Mean time to detect. Clock from when the bad thing started (or first signal) to when you noticed it.",
        },
        {
            "term": "MTTR",
            "plain": "Mean time to respond (or resolve, depending on the org). Clock from detection to containment or close.",
        },
        {
            "term": "FP rate",
            "plain": "False positive rate. Share of alerts that were not real incidents after triage.",
        },
        {
            "term": "Shift quality",
            "plain": "Did cases get summaries, next actions, and clean handoffs? Score beats raw ticket count.",
        },
    ],
    "remember": (
        "Remember: metrics guide improvement. They are not a claim that Boundry runs commercial AI-SOC or 24x7 MDR."
    ),
}

QUIZ: list[dict[str, Any]] = [
    {
        "id": "mq1",
        "stem": "An alert fired at 09:00. You opened it at 09:12 and isolated the host at 09:25. Which span is closest to MTTR?",
        "choices": [
            {"id": "a", "label": "09:00 → 09:12 (detect lag only)"},
            {"id": "b", "label": "09:12 → 09:25 (respond/contain after detect)"},
            {"id": "c", "label": "Whole previous week of quiet"},
        ],
        "answer": "b",
        "explain": "Correct. MTTR starts once you have detected. Common trap: mixing MTTD into MTTR. Remember: detect clock vs respond clock.",
    },
    {
        "id": "mq2",
        "stem": "You closed 8 of 10 Practice alerts as false positive this shift. Rough FP rate?",
        "choices": [
            {"id": "a", "label": "20%"},
            {"id": "b", "label": "80%"},
            {"id": "c", "label": "8 minutes"},
        ],
        "answer": "b",
        "explain": "Correct. FP rate is FPs over total triaged. Common trap: treating count as a time metric. Remember: share of noise, not minutes.",
    },
    {
        "id": "mq3",
        "stem": "A client asks if high FP rate means Boundry is a full MDR. Best answer?",
        "choices": [
            {"id": "a", "label": "Yes, high FP proves 24x7 MDR coverage"},
            {"id": "b", "label": "No. FP rate is a queue-quality signal; it does not equal MDR"},
            {"id": "c", "label": "Ignore the client"},
        ],
        "answer": "b",
        "explain": "Correct. Do not overclaim. Common trap: marketing metrics as service tier. Remember: honest scope.",
    },
]


def list_quiz() -> list[dict[str, Any]]:
    """Public quiz stems."""
    return [
        {
            "id": q["id"],
            "stem": q["stem"],
            "choices": q["choices"],
        }
        for q in QUIZ
    ]


def grade_quiz(answers: dict[str, str]) -> dict[str, Any]:
    """Grade metrics quiz map {qid: choice_id}."""
    if not isinstance(answers, dict):
        return {"ok": False, "error": "Need answers map"}
    correct = 0
    tips: list[str] = []
    for q in QUIZ:
        picked = (answers.get(q["id"]) or "").strip().lower()
        if picked == q["answer"]:
            correct += 1
            tips.append(q["explain"])
        else:
            tips.append(q["explain"].replace("Correct.", "Miss."))
    total = len(QUIZ)
    pct = round(100 * correct / max(total, 1))
    chips = []
    for q in QUIZ:
        picked = (answers.get(q["id"]) or "").strip().lower()
        choice = next((c for c in q["choices"] if c["id"] == q["answer"]), None)
        chips.append(
            career_rationale.chip(
                id=q["id"],
                label=(choice or {}).get("label") or q["answer"],
                matched=picked == q["answer"],
                rationale=q["explain"],
                title="Why this metrics answer",
                row_label=q["stem"][:72] + ("…" if len(q["stem"]) > 72 else ""),
            )
        )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= 70,
        "correct": correct,
        "total": total,
        "tips": tips,
        "teach": SHOW_ME["remember"],
        "answer_chips": chips,
    }


def widget_from_signals(
    *,
    shift_n: int,
    shift_avg: float,
    soc_closed_fp: int,
    soc_closed_total: int,
    handoff_avg: float | None = None,
) -> dict[str, Any]:
    """Small metrics widget numbers from local training signals."""
    fp_rate = (
        round(100 * soc_closed_fp / soc_closed_total, 1)
        if soc_closed_total > 0
        else None
    )
    return {
        "shifts_completed": shift_n,
        "shift_avg_score": round(shift_avg, 1),
        "fp_rate_pct": fp_rate,
        "soc_cases_closed": soc_closed_total,
        "handoff_avg": round(handoff_avg, 1) if handoff_avg is not None else None,
        "disclaimer": "Training signals only. Not a commercial SLA or MDR scorecard.",
    }
