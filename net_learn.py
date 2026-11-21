"""
Net-for-SOC Learn Track — Show me → Help me → Prove it for analyst networking.

SOC-focused (not CCNA). Mirrors Security+/KQL Learn: ordered lessons, per-lesson
practice + quiz, hybrid unlock. Flashcards/drills live in net_lab.py.
"""

from __future__ import annotations

from typing import Any

from net_lessons import LESSONS, PRACTICE, QUIZZES

TRACK_ID = "net"
TRACK_TITLE = "Networking for Analysts"
TRACK_BLURB = (
    "Analyst networking course (SOC-focused, not CCNA). Learn the network facts "
    "Tier-1 cites in tickets: ports that matter, what DNS and HTTP prove, traffic "
    "direction, and how to turn a snippet into enrich / escalate / close. "
    "Show me → Help me → Prove it (≥70%). Flashcards and signal drills stay on the hub."
)

PASS_PCT = 70
CHOICE_LETTERS = "ABCD"


def lesson_ids() -> list[str]:
    """Ordered lesson ids."""
    return [L["id"] for L in LESSONS]


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return one lesson by id."""
    for L in LESSONS:
        if L["id"] == lesson_id:
            return L
    return None


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Help-me checks for a lesson."""
    return PRACTICE.get(lesson_id, [])


def get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Prove-it bank for one lesson (includes answers)."""
    return QUIZZES.get(lesson_id, [])


def _choices_as_letters(choices: list[str]) -> dict[str, str]:
    """Map A–D to choice text."""
    return {CHOICE_LETTERS[i]: text for i, text in enumerate(choices[:4])}


def _letter_to_idx(letter: str) -> int | None:
    """A–D → 0–3."""
    key = (letter or "").strip().upper()
    if len(key) != 1 or key not in CHOICE_LETTERS:
        return None
    return CHOICE_LETTERS.index(key)


def public_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Help-me items without answer_idx (client-safe)."""
    out = []
    for p in get_practice(lesson_id):
        out.append({
            "id": p["id"],
            "prompt": p["prompt"],
            "choices": _choices_as_letters(p["choices"]),
            "hint": p.get("hint") or "",
        })
    return out


def public_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Quiz without answers (client-safe)."""
    return [
        {
            "id": q["id"],
            "q": q["q"],
            "choices": _choices_as_letters(q["choices"]),
        }
        for q in get_quiz(lesson_id)
    ]


def check_practice_answer(lesson_id: str, practice_id: str, picked: str) -> dict[str, Any]:
    """Grade one Help-me check (local, deterministic)."""
    items = get_practice(lesson_id)
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}
    idx = _letter_to_idx(picked)
    correct_idx = int(item["answer_idx"])
    if idx is None:
        return {
            "ok": True,
            "correct": False,
            "verdict": "wrong",
            "explain": "WRONG: pick A-D.",
            "hint": item.get("hint"),
        }
    ok = idx == correct_idx
    return {
        "ok": True,
        "correct": ok,
        "verdict": "correct" if ok else "wrong",
        "explain": item["explain"] if ok else f"WRONG: {item['explain']}",
        "hint": None if ok else item.get("hint"),
        "answer": CHOICE_LETTERS[correct_idx],
    }


def grade_quiz(lesson_id: str, answers: dict[str, str] | None) -> dict[str, Any]:
    """Grade Prove-it for one lesson."""
    bank = get_quiz(lesson_id)
    if not bank:
        return {"ok": False, "error": "Unknown lesson quiz"}
    ans = answers or {}
    graded = []
    correct_n = 0
    for q in bank:
        picked = str(ans.get(q["id"]) or "").strip().upper()
        want = str(q["answer"]).strip().upper()
        ok = picked == want and picked in CHOICE_LETTERS
        if ok:
            correct_n += 1
        graded.append({
            "id": q["id"],
            "q": q["q"],
            "picked": picked or None,
            "answer": want,
            "correct": ok,
            "explain": q["explain"],
        })
    total = len(bank)
    pct = round(100 * correct_n / total) if total else 0
    return {
        "ok": True,
        "lesson_id": lesson_id,
        "correct": correct_n,
        "total": total,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "graded": graded,
    }


def next_incomplete_lesson(passed_lesson_ids: set[str] | list[str] | None) -> dict[str, Any] | None:
    """First lesson without a Prove pass (Continue pointer)."""
    done = set(passed_lesson_ids or [])
    for L in LESSONS:
        if L["id"] not in done:
            return L
    return None


def is_recommended(lesson_id: str, passed_lesson_ids: set[str] | list[str] | None) -> bool:
    """
    Hybrid unlock: lesson 1 always recommended.
    Lesson N is recommended when lesson N-1 has a Prove pass.
    Soft unlock: callers may still open any lesson; hub shows lock styling.
    """
    lesson = get_lesson(lesson_id)
    if not lesson:
        return False
    if int(lesson["order"]) <= 1:
        return True
    done = set(passed_lesson_ids or [])
    prev = None
    for L in LESSONS:
        if int(L["order"]) == int(lesson["order"]) - 1:
            prev = L
            break
    if not prev:
        return True
    return prev["id"] in done
