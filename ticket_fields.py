"""
Shared Ticket Field Console — ITSM-style per-field grading for Career trainers.

Dropdowns + typed sections build muscle memory. Compose a paste-ready note for logs.
"""

from __future__ import annotations

from typing import Any

import career_rationale

CLIENT_OPTIONS = [
    {"id": "Contoso", "label": "Contoso"},
    {"id": "NorthPeak", "label": "NorthPeak"},
    {"id": "Harbor", "label": "Harbor Cannabis"},
]

PRIORITY_OPTIONS = [
    {"id": "p1", "label": "P1 — Immediate"},
    {"id": "p2", "label": "P2 — Urgent"},
    {"id": "p3", "label": "P3 — Schedule / standard"},
    {"id": "p4", "label": "P4 — Accept / low"},
]

# Live SOC Floor also uses P5 (informational / backlog).
LIVE_PRIORITY_OPTIONS = PRIORITY_OPTIONS + [
    {"id": "p5", "label": "P5 — Informational"},
]

DISPOSITION_OPTIONS = [
    {"id": "true_positive", "label": "True positive — investigate / contain"},
    {"id": "false_positive", "label": "False positive — close with note"},
    {"id": "escalate", "label": "Escalate — IR / senior"},
    {"id": "monitor", "label": "Monitor — watch only"},
]

# Field definitions for the console UI (order matters).
STANDARD_FIELDS: list[dict[str, Any]] = [
    {
        "id": "client",
        "label": "Client",
        "control": "select",
        "options": CLIENT_OPTIONS,
        "required": True,
        "hint": "Tag the correct Practice client.",
    },
    {
        "id": "priority",
        "label": "Priority",
        "control": "select",
        "options": PRIORITY_OPTIONS,
        "required": True,
        "hint": "How fast this must move (SLA thinking).",
    },
    {
        "id": "disposition",
        "label": "Disposition",
        "control": "select",
        "options": DISPOSITION_OPTIONS,
        "required": True,
        "hint": "How you close or escalate the case.",
    },
    {
        "id": "what_happened",
        "label": "What happened",
        "control": "textarea",
        "required": True,
        "hint": "Short summary of the alert / story.",
        "placeholder": "e.g. Password spray from one IP against 12 Contoso users…",
    },
    {
        "id": "evidence",
        "label": "Evidence / IOC",
        "control": "textarea",
        "required": True,
        "hint": "Cite the indicator and what enrich found.",
        "placeholder": "e.g. IOC 203.0.113.44 — enrich suspicious, no allowlist…",
    },
    {
        "id": "actions_taken",
        "label": "Actions taken",
        "control": "textarea",
        "required": True,
        "hint": "What you approved, denied, or already did.",
        "placeholder": "e.g. Approved 24h edge block; sessions still under watch…",
    },
    {
        "id": "next_action",
        "label": "Next action",
        "control": "textarea",
        "required": True,
        "hint": "Who does what next (you, IR, client, Ops).",
        "placeholder": "e.g. Monitor for successful logons; escalate if any succeed…",
    },
]

FIELD_IDS = [f["id"] for f in STANDARD_FIELDS]


def fields_for_ui(*, omit: list[str] | None = None) -> list[dict[str, Any]]:
    """Return field defs for template JSON, optionally omitting ids (e.g. Shift client)."""
    skip = set(omit or [])
    return [dict(f) for f in STANDARD_FIELDS if f["id"] not in skip]


def fields_for_live_ops() -> list[dict[str, Any]]:
    """Live Floor fields: no client (on ticket meta), no actions_taken column."""
    fields = fields_for_ui(omit=["client", "actions_taken"])
    for f in fields:
        if f["id"] == "priority":
            f["options"] = list(LIVE_PRIORITY_OPTIONS)
            f["hint"] = "How fast this must move (SLA thinking)."
    return fields


def priority_to_int(pid: str) -> int:
    """Map p1–p5 field ids to Live priority integers."""
    try:
        n = int(str(pid or "").lower().lstrip("p") or "3")
    except ValueError:
        n = 3
    return max(1, min(5, n))


def priority_from_int(n: Any) -> str:
    """Map Live priority int to pN field id."""
    try:
        v = int(n)
    except (TypeError, ValueError):
        v = 3
    return f"p{max(1, min(5, v))}"


def compose_note(submitted: dict[str, Any]) -> str:
    """Compose labeled ticket body from field values."""
    client = (submitted.get("client") or "").strip()
    priority = (submitted.get("priority") or "").strip()
    disposition = (submitted.get("disposition") or "").strip()
    what = (submitted.get("what_happened") or "").strip()
    evidence = (submitted.get("evidence") or "").strip()
    actions = (submitted.get("actions_taken") or "").strip()
    nxt = (submitted.get("next_action") or "").strip()
    lines = [
        f"Client: {client}" if client else "",
        f"Priority: {priority}" if priority else "",
        f"Disposition: {disposition}" if disposition else "",
        f"What: {what}" if what else "",
        f"Evidence: {evidence}" if evidence else "",
        f"Actions: {actions}" if actions else "",
        f"Next: {nxt}" if nxt else "",
    ]
    return "\n".join(x for x in lines if x)


def _label_for(field_id: str, value: str) -> str:
    """Human label for a dropdown value."""
    for f in STANDARD_FIELDS:
        if f["id"] != field_id:
            continue
        for opt in f.get("options") or []:
            if opt["id"] == value:
                return opt["label"]
    return value


def _typed_ok(value: str, rule: dict[str, Any]) -> bool:
    """Grade a typed field against min_len + must_include keywords."""
    text = (value or "").strip()
    min_len = int(rule.get("min_len") or 8)
    if len(text) < min_len:
        return False
    must = [str(k).lower() for k in (rule.get("must_include") or [])]
    if not must:
        return True
    low = text.lower()
    need = int(rule.get("min_hits") or max(1, (len(must) + 1) // 2))
    hits = sum(1 for k in must if k in low)
    return hits >= need


def grade_ticket_fields(
    expected: dict[str, Any],
    submitted: dict[str, Any] | None,
    *,
    omit: list[str] | None = None,
) -> dict[str, Any]:
    """
    Grade submitted ticket fields against expected rules.

    expected[field_id] for select: {"value": "Contoso"} or {"values": ["a","b"]}
    expected[field_id] for typed: {"must_include": [...], "min_len": 8, "min_hits": 1}
    """
    submitted = submitted or {}
    skip = set(omit or [])
    results: list[dict[str, Any]] = []
    chips: list[dict[str, Any]] = []
    hit = 0
    graded_ids = [fid for fid in FIELD_IDS if fid not in skip and fid in expected]

    for fid in graded_ids:
        rule = expected.get(fid) or {}
        got = (submitted.get(fid) or "").strip()
        field_meta = next((f for f in STANDARD_FIELDS if f["id"] == fid), None)
        control = (field_meta or {}).get("control") or "textarea"
        label = (field_meta or {}).get("label") or fid

        if control == "select":
            allowed = rule.get("values") or (
                [rule["value"]] if rule.get("value") else []
            )
            ok = bool(got) and got in allowed
            correct_show = ", ".join(_label_for(fid, v) for v in allowed) or "(set)"
            rationale = (
                f"Correct {label.lower()}: {correct_show}. "
                + (rule.get("why") or "Pick the field that matches the case facts.")
            )
        else:
            ok = _typed_ok(got, rule)
            keys = rule.get("must_include") or []
            correct_show = (
                f"Include ideas like: {', '.join(keys)}"
                if keys
                else "Write a clear short note (enough detail)."
            )
            rationale = (
                f"{label}: {correct_show}. "
                + (rule.get("why") or "Cite the case so the next analyst can act.")
            )

        if ok:
            hit += 1
        results.append(
            {
                "id": fid,
                "label": label,
                "correct": ok,
                "got": got,
                "expected_display": correct_show,
            }
        )
        chips.append(
            career_rationale.chip(
                id=f"tf_{fid}",
                label=correct_show[:72] + ("…" if len(correct_show) > 72 else ""),
                matched=ok,
                rationale=rationale,
                title=f"Why this {label.lower()}",
                row_label=f"Correct {label.lower()}",
            )
        )

    total = max(len(graded_ids), 1)
    pct = round(100 * hit / total)
    note = compose_note(submitted)
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= 70 and hit == total,
        "field_results": results,
        "answer_chips": chips,
        "composed_note": note,
        "hits": hit,
        "total": total,
    }
