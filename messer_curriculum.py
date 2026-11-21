"""
Private SY0-701 curriculum from Messer session spine (121 sessions).

Loaded from content/private/messer/curriculum/701_curriculum.json — not committed to git.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from messer_paths import messer_work_dir
from practice_feedback import prove_item_explain

TRACK_ID = "secplus"
TRACK_TITLE = "Security+ SY0-701 Lab (Messer)"
TRACK_BLURB = (
    "CompTIA SY0-701 study path built from your licensed Messer pack: "
    "121 video-aligned sessions, course notes Show-me, Messer Help-me and Prove banks. "
    "Private to this machine; not in git."
)
PASS_PCT = 70
CHOICE_LETTERS = "ABCD"

_payload: dict[str, Any] | None = None
_loaded_mtime: float = 0.0
DOMAINS: list[dict[str, Any]] = []
LESSONS: list[dict[str, Any]] = []
PRACTICE: dict[str, list[dict[str, Any]]] = {}
QUIZZES: dict[str, list[dict[str, Any]]] = {}
PRACTICE_EXAM_FALLBACK: dict[str, list[dict[str, Any]]] = {}
PBQS: dict[str, dict[str, Any]] = {}


def curriculum_path() -> Path:
    return messer_work_dir() / "curriculum" / "701_curriculum.json"


def load() -> bool:
    """Load curriculum JSON into module globals. Returns False if missing."""
    global _payload, _loaded_mtime, DOMAINS, LESSONS, PRACTICE, QUIZZES, PRACTICE_EXAM_FALLBACK, PBQS
    p = curriculum_path()
    if not p.is_file():
        _payload = None
        _loaded_mtime = 0.0
        return False
    mtime = p.stat().st_mtime
    if _payload is not None and mtime == _loaded_mtime and LESSONS:
        return True
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    _loaded_mtime = mtime
    _payload = data
    DOMAINS = list(data.get("domains") or [])
    LESSONS = list(data.get("lessons") or [])
    PRACTICE = dict(data.get("practice") or {})
    QUIZZES = dict(data.get("quizzes") or {})
    PRACTICE_EXAM_FALLBACK = dict(data.get("practice_exam_fallback") or {})
    PBQS = dict(data.get("pbqs") or {})
    return bool(LESSONS)


def is_ready() -> bool:
    if _payload is None:
        load()
    return bool(LESSONS)


def domain_ids() -> list[str]:
    return [d["id"] for d in DOMAINS]


def get_domain(domain_id: str) -> dict[str, Any] | None:
    for d in DOMAINS:
        if d["id"] == domain_id:
            return d
    return None


def lesson_ids() -> list[str]:
    return [L["id"] for L in LESSONS]


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    for L in LESSONS:
        if L["id"] == lesson_id:
            return L
    return None


def lessons_for_domain(domain_id: str) -> list[dict[str, Any]]:
    return [L for L in LESSONS if L["domain_id"] == domain_id]


def _notes_for_lesson(lesson_id: str) -> str:
    from tools.messer_notes_quiz_batch import study_source_body

    lesson = get_lesson(lesson_id)
    return study_source_body(lesson or {}) if lesson else ""


def _filter_valid_practice(lesson_id: str, bank: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from notes_quiz_guards import validate_notes_mcq

    notes = _notes_for_lesson(lesson_id)
    good: list[dict[str, Any]] = []
    for p in bank:
        try:
            validate_notes_mcq({
                "prompt": p.get("prompt"),
                "choices": p.get("choices"),
                "answer_idx": p.get("answer_idx"),
                "explain": p.get("explain") or p.get("correct_explain"),
            }, notes=notes)
            good.append(p)
        except ValueError:
            continue
    return good


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    bank = _filter_valid_practice(lesson_id, PRACTICE.get(lesson_id, []))
    if bank:
        return bank
    return list(PRACTICE_EXAM_FALLBACK.get(lesson_id) or [])


def get_pbq(lesson_id: str) -> dict[str, Any] | None:
    return PBQS.get(lesson_id)


def get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    from tools.messer_notes_quiz_batch import PROVE_MIN

    notes = _notes_for_lesson(lesson_id)
    from notes_quiz_guards import validate_notes_mcq

    good: list[dict[str, Any]] = []
    for q in QUIZZES.get(lesson_id, []):
        try:
            validate_notes_mcq({
                "prompt": q.get("q") or q.get("prompt"),
                "choices": q.get("choices"),
                "answer_idx": q.get("answer_idx"),
                "explain": q.get("explain"),
            }, notes=notes)
            good.append(q)
        except ValueError:
            continue
    if len(good) >= PROVE_MIN:
        return good
    return []


def _choices_as_letters(choices: list[str]) -> dict[str, str]:
    return {CHOICE_LETTERS[i]: text for i, text in enumerate(choices[:4])}


def _letter_to_idx(letter: str) -> int | None:
    key = (letter or "").strip().upper()
    if len(key) != 1 or key not in CHOICE_LETTERS:
        return None
    return CHOICE_LETTERS.index(key)


def public_practice(lesson_id: str) -> list[dict[str, Any]]:
    from practice_hints import resolve_practice_hint
    from practice_scenario_context import build_scenario_context
    from practice_text_format import format_reading_block

    out = []
    for p in get_practice(lesson_id):
        hint = resolve_practice_hint(p)
        out.append({
            "id": p["id"],
            "prompt": p["prompt"],
            "choices": _choices_as_letters(p["choices"]),
            "hint": hint,
            "hint_formatted": format_reading_block(hint, fallback_term="Memory hook", role="hint"),
            "scenario": build_scenario_context(p.get("prompt") or "", lesson_id),
        })
    return out


def public_pbq(lesson_id: str) -> dict[str, Any] | None:
    pbq = get_pbq(lesson_id)
    if not pbq:
        return None
    kind = pbq["kind"]
    base = {"id": pbq["id"], "kind": kind, "title": pbq["title"], "prompt": pbq["prompt"]}
    if kind == "pick":
        base["choices"] = [{"id": c["id"], "text": c["text"]} for c in pbq["choices"]]
    elif kind in ("order", "map"):
        base["steps"] = [{"id": s["id"], "text": s["text"]} for s in pbq.get("items") or []]
    return base


def public_quiz(lesson_id: str) -> list[dict[str, Any]]:
    return [
        {"id": q["id"], "q": q["q"], "choices": _choices_as_letters(q["choices"])}
        for q in get_quiz(lesson_id)
    ]


def check_practice_answer(lesson_id: str, practice_id: str, picked: str) -> dict[str, Any]:
    from practice_feedback import practice_check_payload

    items = get_practice(lesson_id)
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}
    return practice_check_payload(
        item, picked, lesson_id=lesson_id, choice_letters=CHOICE_LETTERS,
    )


def check_pbq_answer(lesson_id: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {"ok": False, "error": "No PBQ on this session"}


def grade_quiz(lesson_id: str, answers: dict[str, str]) -> dict[str, Any]:
    bank = get_quiz(lesson_id)
    if not bank:
        return {
            "ok": False,
            "error": "Unknown lesson quiz",
            "correct": 0,
            "total": 0,
            "pct": 0,
            "passed": False,
            "graded": [],
        }
    graded = []
    correct_n = 0
    for q in bank:
        picked = (answers.get(q["id"]) or "").strip().upper()
        want_idx = int(q["answer_idx"])
        want = CHOICE_LETTERS[want_idx]
        ok = picked == want
        if ok:
            correct_n += 1
        graded.append({
            "id": q["id"],
            "correct": ok,
            "picked": picked,
            "answer": want,
            "explain": prove_item_explain(q, picked, ok=ok, choice_letters=CHOICE_LETTERS),
            "q": q["q"],
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
    done = set(passed_lesson_ids or [])
    for L in LESSONS:
        if L["id"] not in done:
            return L
    return None


def domain_lessons_passed(domain_id: str, passed_lesson_ids: set[str] | list[str] | None) -> tuple[int, int]:
    done = set(passed_lesson_ids or [])
    ids = [L["id"] for L in lessons_for_domain(domain_id)]
    return len([i for i in ids if i in done]), len(ids)


def domains_fully_passed(passed_lesson_ids: set[str] | list[str] | None) -> list[str]:
    done = set(passed_lesson_ids or [])
    green = []
    for d in DOMAINS:
        ids = [L["id"] for L in lessons_for_domain(d["id"])]
        if ids and all(i in done for i in ids):
            green.append(d["id"])
    return green


def weakest_lesson(passed_lesson_ids: set[str] | list[str] | None) -> str | None:
    nxt = next_incomplete_lesson(passed_lesson_ids)
    return nxt["id"] if nxt else None


def weakest_domain(
    passed_domain_ids: set[str] | list[str] | None = None,
    passed_lesson_ids: set[str] | list[str] | None = None,
) -> str | None:
    if passed_lesson_ids is not None:
        green = set(domains_fully_passed(passed_lesson_ids))
        for d in DOMAINS:
            if d["id"] not in green:
                return d["id"]
        return None
    done = set(passed_domain_ids or [])
    for d in DOMAINS:
        if d["id"] not in done:
            return d["id"]
    return None


def all_key_terms() -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for L in LESSONS:
        for term in L.get("key_terms") or []:
            key = term.strip()
            if not key or key.lower() in {k.lower() for k in seen}:
                continue
            seen[key] = {
                "term": key,
                "lesson_id": L["id"],
                "lesson_title": L["title"],
                "domain_id": L["domain_id"],
                "objective_ref": L["objective_ref"],
            }
    return list(seen.values())


def quiz_answer_indices(lesson_id: str) -> list[int]:
    return [int(q["answer_idx"]) for q in get_quiz(lesson_id)]


def must_cover_objectives() -> list[str]:
    return sorted({L["objective_ref"] for L in LESSONS if L.get("objective_ref")})
