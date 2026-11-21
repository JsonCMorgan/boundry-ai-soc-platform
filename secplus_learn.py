"""
Security+ Lab - Phase 1 personal tutor (micro-lessons; SY0-701 study path).

Show me → Help me → Watch me (optional PBQ) → Prove it (≥70%).
Pattern mirrors KQL Learn (ordered lessons, per-lesson practice + quiz).
Original Boundry content only. Official objective IDs as outline, never dumps.
"""

from __future__ import annotations

from typing import Any

from practice_feedback import prove_item_explain
from secplus_lessons import DOMAINS, LESSONS, PRACTICE, QUIZZES, PBQS

TRACK_ID = "secplus"


def _messer_track():
    """Private Messer 701 curriculum when ENABLE_MESSER_LAYER and JSON exist."""
    try:
        import messer_layer
        import messer_curriculum
    except ImportError:
        return None
    if not messer_layer.messer_enabled():
        return None
    if messer_curriculum.is_ready():
        return messer_curriculum
    return None


def active_domains() -> list[dict[str, Any]]:
    t = _messer_track()
    return t.DOMAINS if t else DOMAINS


def active_lessons() -> list[dict[str, Any]]:
    t = _messer_track()
    return t.LESSONS if t else LESSONS


def active_track_title() -> str:
    t = _messer_track()
    return t.TRACK_TITLE if t else TRACK_TITLE


def active_track_blurb() -> str:
    t = _messer_track()
    return t.TRACK_BLURB if t else TRACK_BLURB


TRACK_TITLE = "Security+ SY0-801 Lab"
TRACK_BLURB = (
    "Your Security+ tutor for CompTIA SY0-701 (current Messer pack and exam version). "
    "Bite-sized lessons in exam order D1→D5: show-me depth, Help me, then Prove it (≥70%). "
    "Show me → Help me → Watch me (PBQs) → Prove it. With ENABLE_MESSER_LAYER, private Messer "
    "materials augment or replace lesson banks on your machine only. Domain 4 ties to Shift/SPL/KQL/SOAR. "
    "SY0-801 alignment waits until 801 course materials exist."
)

PASS_PCT = 70
CHOICE_LETTERS = "ABCD"


def domain_ids() -> list[str]:
    """Ordered domain ids."""
    return [d["id"] for d in active_domains()]


def get_domain(domain_id: str) -> dict[str, Any] | None:
    """Return domain metadata by id."""
    for d in active_domains():
        if d["id"] == domain_id:
            return d
    return None


def lesson_ids() -> list[str]:
    """Ordered lesson ids (D1→D5 spine)."""
    return [L["id"] for L in active_lessons()]


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return one micro-lesson by id."""
    t = _messer_track()
    if t:
        return t.get_lesson(lesson_id)
    for L in LESSONS:
        if L["id"] == lesson_id:
            return L
    return None


def lessons_for_domain(domain_id: str) -> list[dict[str, Any]]:
    """Lessons belonging to a domain, in spine order."""
    t = _messer_track()
    if t:
        return t.lessons_for_domain(domain_id)
    return [L for L in LESSONS if L["domain_id"] == domain_id]


def _boundry_get_practice(lesson_id: str) -> list[dict[str, Any]]:
    return PRACTICE.get(lesson_id, [])


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Help-me checks for a lesson."""
    t = _messer_track()
    if t:
        return t.get_practice(lesson_id)
    return _boundry_get_practice(lesson_id)


def _boundry_get_pbq(lesson_id: str) -> dict[str, Any] | None:
    return PBQS.get(lesson_id)


def get_pbq(lesson_id: str) -> dict[str, Any] | None:
    """Watch-me PBQ if this lesson is tagged; else None."""
    t = _messer_track()
    if t:
        return t.get_pbq(lesson_id)
    return _boundry_get_pbq(lesson_id)


def _boundry_get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    return QUIZZES.get(lesson_id, [])


def get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Prove-it bank for one lesson (includes answers)."""
    t = _messer_track()
    if t:
        return t.get_quiz(lesson_id)
    return _boundry_get_quiz(lesson_id)


def lesson_has_quiz(lesson_id: str) -> bool:
    """True when this session has the minimum notes Prove-it bank."""
    from tools.messer_notes_quiz_batch import PROVE_MIN

    return len(get_quiz(lesson_id)) >= PROVE_MIN


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
    t = _messer_track()
    if t:
        return t.public_practice(lesson_id)
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
    """PBQ without answers (client-safe)."""
    t = _messer_track()
    if t:
        return t.public_pbq(lesson_id)
    pbq = get_pbq(lesson_id)
    if not pbq:
        return None
    kind = pbq["kind"]
    base = {
        "id": pbq["id"],
        "kind": kind,
        "title": pbq["title"],
        "prompt": pbq["prompt"],
    }
    if kind == "pick":
        base["choices"] = [{"id": c["id"], "text": c["text"]} for c in pbq["choices"]]
    elif kind == "order":
        base["steps"] = [{"id": s["id"], "text": s["text"]} for s in pbq["items"]]
    elif kind == "map":
        base["categories"] = list(pbq["categories"])
        # Template expects steps (same shape as order UI rows).
        base["steps"] = [{"id": it["id"], "text": it["text"]} for it in pbq["items"]]
    return base


def public_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Quiz without answers (client-safe)."""
    t = _messer_track()
    if t:
        return t.public_quiz(lesson_id)
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
    from practice_feedback import practice_check_payload

    t = _messer_track()
    if t:
        return t.check_practice_answer(lesson_id, practice_id, picked)
    items = get_practice(lesson_id)
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}
    return practice_check_payload(
        item, picked, lesson_id=lesson_id, choice_letters=CHOICE_LETTERS,
    )


def check_pbq_answer(lesson_id: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Grade Watch-me PBQ (map / order / pick)."""
    t = _messer_track()
    if t:
        return t.check_pbq_answer(lesson_id, payload)
    pbq = get_pbq(lesson_id)
    if not pbq:
        return {"ok": False, "error": "Unknown PBQ"}
    data = payload or {}
    kind = pbq["kind"]

    if kind == "pick":
        picked = str(data.get("picked") or "").strip()
        ok = picked == pbq["answer"]
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else f"WRONG: {pbq['explain']}",
            "answer": pbq["answer"],
        }

    if kind == "order":
        user_order = data.get("order") or []
        if not isinstance(user_order, list):
            user_order = []
        user_order = [str(x) for x in user_order]
        want = list(pbq["correct_order"])
        ok = user_order == want
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else (
                "WRONG order. Wanted: " + " → ".join(want) + ". " + str(pbq["explain"])
            ),
            "answer": want,
        }

    if kind == "map":
        mapping = data.get("mapping") or {}
        if not isinstance(mapping, dict):
            mapping = {}
        expected = {it["id"]: it["answer"] for it in pbq["items"]}
        misses = [iid for iid, want in expected.items() if str(mapping.get(iid) or "").strip() != want]
        ok = not misses
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else f"WRONG: {len(misses)} mapping(s) off. {pbq['explain']}",
            "answer": expected,
            "misses": misses,
        }

    return {"ok": False, "error": f"Unsupported PBQ kind: {kind}"}


def grade_quiz(lesson_id: str, answers: dict[str, str]) -> dict[str, Any]:
    """Grade prove-it submission {question_id: letter}."""
    t = _messer_track()
    if t:
        return t.grade_quiz(lesson_id, answers)
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
    """First lesson on D1→D5 spine without a Prove pass (Continue pointer)."""
    t = _messer_track()
    if t:
        return t.next_incomplete_lesson(passed_lesson_ids)
    done = set(passed_lesson_ids or [])
    for L in LESSONS:
        if L["id"] not in done:
            return L
    return None


def domain_lessons_passed(domain_id: str, passed_lesson_ids: set[str] | list[str] | None) -> tuple[int, int]:
    """(passed_count, total) for one domain's micro-lessons."""
    t = _messer_track()
    if t:
        return t.domain_lessons_passed(domain_id, passed_lesson_ids)
    done = set(passed_lesson_ids or [])
    ids = [L["id"] for L in lessons_for_domain(domain_id)]
    return len([i for i in ids if i in done]), len(ids)


def domains_fully_passed(passed_lesson_ids: set[str] | list[str] | None) -> list[str]:
    """Domain ids where every micro-lesson has Prove pass."""
    t = _messer_track()
    if t:
        return t.domains_fully_passed(passed_lesson_ids)
    done = set(passed_lesson_ids or [])
    green = []
    for d in DOMAINS:
        ids = [L["id"] for L in lessons_for_domain(d["id"])]
        if ids and all(i in done for i in ids):
            green.append(d["id"])
    return green


def weakest_lesson(passed_lesson_ids: set[str] | list[str] | None) -> str | None:
    """Lesson id for Saturday CTA / Continue (first incomplete)."""
    t = _messer_track()
    if t:
        return t.weakest_lesson(passed_lesson_ids)
    nxt = next_incomplete_lesson(passed_lesson_ids)
    return nxt["id"] if nxt else None


def weakest_domain(passed_domain_ids: set[str] | list[str] | None = None,
                   passed_lesson_ids: set[str] | list[str] | None = None) -> str | None:
    """
    First unfinished domain in exam order.
    Prefer lesson-level progress when provided.
    """
    t = _messer_track()
    if t:
        return t.weakest_domain(passed_domain_ids, passed_lesson_ids)
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
    """Curated term bank: unique key_terms with first lesson reference."""
    t = _messer_track()
    if t:
        return t.all_key_terms()
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
    """answer_idx list for smoke tests."""
    return [int(q["answer_idx"]) for q in get_quiz(lesson_id)]


def must_cover_objectives() -> list[str]:
    """Sorted unique objective_ref codes present in the spine."""
    return sorted({L["objective_ref"] for L in active_lessons()})
