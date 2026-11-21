"""Structured Help-me / practice feedback (Messer imports + Boundry lessons)."""

from __future__ import annotations

import json
import re
from typing import Any

CHOICE_LETTERS = "ABCD"


def parse_messer_incorrect_answers(text: str) -> dict[str, str]:
    """Parse Messer 'The incorrect answers:' block into letter → explanation."""
    out: dict[str, str] = {}
    if not text:
        return out
    blob = text
    if "The incorrect answers:" in blob:
        blob = blob.split("The incorrect answers:", 1)[1]
    blob = blob.strip()
    if not blob:
        return out
    pattern = re.compile(
        r"(?:^|\n)([A-F])[\.)]\s*([^\n]+)\n([\s\S]*?)(?=\n[A-F][\.)]\s|\Z)",
        re.MULTILINE,
    )
    for m in pattern.finditer(blob):
        letter = m.group(1).upper()
        title = re.sub(r"\s+", " ", m.group(2).strip())
        body = re.sub(r"\s+", " ", m.group(3).strip())
        if body:
            out[letter] = f"{title} — {body}"
        else:
            out[letter] = title
    return out


def _letters_for_choices(choices: list[str]) -> list[str]:
    return list(CHOICE_LETTERS[: min(len(choices), 4)])


def _strip_tutor_correct_prefix(text: str) -> str:
    """Remove leading 'Correct.' from stored tutor explain (wrong-answer reuse)."""
    t = (text or "").strip()
    low = t.lower()
    if low.startswith("correct."):
        return t[8:].strip()
    if low.startswith("correct:"):
        return t[8:].strip()
    if low.startswith("correct "):
        return t[8:].strip()
    return t


def _choice_label_only(text: str) -> str:
    """Drop a leading A. / B) prefix so UI does not show 'B. B. …'."""
    return re.sub(r"^[A-D][\.)]\s*", "", (text or "").strip(), count=1, flags=re.I)


def _text_for_letter(
    letter: str,
    *,
    choices: list[str],
    letters: list[str],
    correct_letter: str,
    incorrect: dict[str, str],
    correct_explain: str,
) -> str:
    idx = letters.index(letter)
    label = choices[idx]
    if letter == correct_letter:
        if correct_explain.strip():
            return correct_explain.strip()
        return (
            f"{label} fits this scenario. "
            "Re-read the course notes if you want a deeper definition."
        )
    parsed = incorrect.get(letter)
    if parsed:
        return parsed
    return f"{label} is not the best answer for what this question describes."


def build_practice_review(
    *,
    choices: list[str],
    answer_idx: int,
    picked_letter: str,
    explain_raw: str = "",
    correct_explain: str = "",
    choice_reviews: dict[str, str] | None = None,
    scenario: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ordered review sections for wrong answers (UI accordion)."""
    letters = _letters_for_choices(choices)
    if not letters or answer_idx < 0 or answer_idx >= len(letters):
        return {"lead": "", "sections": []}
    correct_letter = letters[answer_idx]
    picked = (picked_letter or "").strip().upper()[:1]
    incorrect = parse_messer_incorrect_answers(explain_raw)
    if choice_reviews:
        for letter, text in choice_reviews.items():
            if letter in letters and text:
                if letter == correct_letter:
                    correct_explain = text
                else:
                    incorrect[letter] = text

    def explain(letter: str) -> str:
        return _text_for_letter(
            letter,
            choices=choices,
            letters=letters,
            correct_letter=correct_letter,
            incorrect=incorrect,
            correct_explain=correct_explain,
        )

    from practice_text_format import format_lead_block, format_reading_block

    sections: list[dict[str, Any]] = []

    def _section(letter: str, label: str, role: str, title: str) -> dict[str, Any]:
        text = explain(letter)
        return {
            "letter": letter,
            "label": label,
            "role": role,
            "title": title,
            "text": text,
            "formatted": format_reading_block(text, fallback_term=label, role=role),
        }

    if picked and picked in letters and picked != correct_letter:
        sections.append(_section(
            picked,
            choices[letters.index(picked)],
            "your_pick",
            "Your pick",
        ))

    for i, letter in enumerate(letters):
        if letter == correct_letter or letter == picked:
            continue
        sections.append(_section(letter, choices[i], "other_wrong", "Also wrong"))

    sections.append(_section(
        correct_letter,
        choices[answer_idx],
        "correct",
        "Correct answer",
    ))

    if picked and picked != correct_letter:
        lead = (
            f"You picked {picked}. {choices[letters.index(picked)]}. "
            "After the scenario definition above, see why that misses here, then compare the other options."
        )
    else:
        lead = "Review the scenario definition, then each option below."

    return {
        "scenario": scenario,
        "lead": lead,
        "lead_formatted": format_lead_block(lead),
        "sections": sections,
    }


def prove_item_explain(
    item: dict[str, Any],
    picked_letter: str,
    *,
    ok: bool,
    choice_letters: str = CHOICE_LETTERS,
) -> str:
    """Explain line for Prove-it results (avoid 'Correct.' under a red X)."""
    if ok:
        return (item.get("explain") or "Correct.").strip()

    choices = item.get("choices") or []
    answer_idx = int(item.get("answer_idx", 0))
    letters = _letters_for_choices(choices)
    if not letters or answer_idx < 0 or answer_idx >= len(letters):
        return "Not quite. Re-read this session's course notes and try again."

    want = letters[answer_idx]
    correct_label = _choice_label_only(choices[answer_idx])
    why = _strip_tutor_correct_prefix(item.get("explain") or "")
    picked = (picked_letter or "").strip().upper()[:1]

    if picked and picked in letters:
        picked_label = _choice_label_only(choices[letters.index(picked)])
        msg = f"Not quite. You picked {picked}. {picked_label}."
    else:
        msg = "Not quite."

    msg += f" Best answer: {want}. {correct_label}."
    if why:
        msg += f" {why}"
    return msg.strip()[:1200]


def practice_check_payload(
    item: dict[str, Any],
    picked_letter: str,
    *,
    lesson_id: str | None = None,
    choice_letters: str = CHOICE_LETTERS,
) -> dict[str, Any]:
    """Grade one practice item and attach structured feedback when wrong."""
    key = (picked_letter or "").strip().upper()
    if len(key) != 1 or key not in choice_letters:
        return {
            "ok": True,
            "correct": False,
            "verdict": "wrong",
            "explain": "WRONG: pick A-D.",
            "hint": item.get("hint"),
        }

    correct_idx = int(item["answer_idx"])
    picked_idx = choice_letters.index(key)
    ok = picked_idx == correct_idx
    choices = item.get("choices") or []
    correct_explain = (item.get("correct_explain") or "").strip()
    if not correct_explain:
        prov = item.get("provenance")
        if isinstance(prov, str):
            try:
                prov = json.loads(prov)
            except json.JSONDecodeError:
                prov = {}
        if isinstance(prov, dict):
            correct_explain = (prov.get("correct_explain") or "").strip()

    from practice_hints import resolve_practice_hint

    payload: dict[str, Any] = {
        "ok": True,
        "correct": ok,
        "verdict": "correct" if ok else "wrong",
        "answer": choice_letters[correct_idx],
        "hint": None if ok else resolve_practice_hint(item),
    }
    from practice_scenario_context import build_scenario_context
    from practice_text_format import format_reading_block

    prompt = item.get("prompt") or item.get("stem") or item.get("q") or ""
    scenario = build_scenario_context(prompt, lesson_id)

    if ok:
        explain_text = correct_explain or item.get("explain") or "Correct."
        payload["explain"] = explain_text
        payload["explain_formatted"] = format_reading_block(
            explain_text,
            fallback_term=choices[correct_idx] if correct_idx < len(choices) else "",
            role="correct",
        )
        payload["scenario"] = scenario
        return payload

    review = build_practice_review(
        choices=choices,
        answer_idx=correct_idx,
        picked_letter=key,
        explain_raw=item.get("explain") or "",
        correct_explain=correct_explain,
        choice_reviews=item.get("choice_reviews"),
        scenario=scenario,
    )
    payload["review"] = review
    payload["explain"] = review["lead"]
    hint_text = payload.get("hint") or ""
    if hint_text:
        from practice_text_format import format_reading_block

        payload["hint_formatted"] = format_reading_block(
            hint_text, fallback_term="Memory hook", role="hint",
        )
    return payload
