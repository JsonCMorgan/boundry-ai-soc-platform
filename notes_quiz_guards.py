"""Deterministic validation for notes-grounded Help / Prove MCQs."""

from __future__ import annotations

import re
from typing import Any

from tools.messer_notes_quiz_batch import PROVE_MIN  # noqa: F401 — re-export


def validate_notes_mcq(mcq: dict[str, Any], *, notes: str = "", label: str = "mcq") -> None:
    """Raise ValueError if MCQ fails concept or notes-contradiction checks."""
    _assert_mcq_concepts(mcq)
    if notes.strip():
        _assert_notes_alignment(mcq, notes)


def _assert_mcq_concepts(mcq: dict[str, Any]) -> None:
    """Reject common LLM inversions for high-stakes terms."""
    prompt_l = (mcq.get("prompt") or mcq.get("q") or "").lower()
    explain_l = (mcq.get("explain") or "").lower()
    choices = mcq.get("choices") or []
    answer_idx = int(mcq.get("answer_idx", 0))
    if answer_idx < 0 or answer_idx >= len(choices):
        return
    correct_l = str(choices[answer_idx]).lower()
    if "non-repudiation" not in prompt_l and "non repudiation" not in prompt_l:
        return

    def wrongly_affirms_deny(text: str) -> bool:
        if re.search(r"(cannot|can't|can not|unable to)\s+deny", text):
            return False
        if re.search(r"cannot credibly deny|can't deny what you", text):
            return False
        if re.search(r"ability to deny|deny what you", text):
            return True
        if "taking it back" in text and "cannot" not in text and "can't" not in text:
            return True
        return False

    if wrongly_affirms_deny(correct_l) or wrongly_affirms_deny(explain_l):
        raise ValueError(
            "non-repudiation MCQ treats deny as correct; must be cannot deny / prove who signed or sent"
        )


def _assert_notes_alignment(mcq: dict[str, Any], notes: str) -> None:
    """Flag marked correct answers that contradict negation in notes near the topic."""
    prompt = (mcq.get("prompt") or mcq.get("q") or "").lower()
    choices = mcq.get("choices") or []
    answer_idx = int(mcq.get("answer_idx", 0))
    if answer_idx < 0 or answer_idx >= len(choices):
        return
    correct = str(choices[answer_idx]).lower()
    notes_l = notes.lower()

    _assert_sensor_notes_alignment(prompt, correct, choices, answer_idx, notes_l)

    if "non-repudiation" in prompt or "non repudiation" in prompt:
        if ("can't deny" in notes_l or "cannot deny" in notes_l) and re.search(
            r"ability to deny|deny what you", correct
        ):
            if "cannot" not in correct and "can't" not in correct:
                raise ValueError("correct choice contradicts notes on non-repudiation (cannot deny)")


def _assert_sensor_notes_alignment(
    prompt: str,
    correct: str,
    choices: list[Any],
    answer_idx: int,
    notes_l: str,
) -> None:
    """Physical-security sensor bullets in Messer notes (0102-06 style)."""
    if "sensor" not in prompt and "motion" not in prompt:
        return
    if "large area" in prompt or "large areas" in prompt:
        if "movement across large" in notes_l or "large areas" in notes_l:
            if "microwave" in notes_l and "microwave" not in correct:
                raise ValueError(
                    "marked answer should be microwave for large-area motion (per course notes)"
                )
    if "floor" in prompt or "window" in prompt:
        if "change in force" in notes_l and "pressure" in notes_l:
            if "pressure" not in correct and "floor" in prompt:
                raise ValueError("marked answer should be pressure for floor/window sensors (per notes)")


def validate_prove_bank(
    quizzes: list[dict[str, Any]],
    *,
    notes: str = "",
    help_prompts: set[str] | None = None,
    min_count: int = 5,
) -> None:
    """Ensure Prove bank size and per-item validation."""
    if len(quizzes) < min_count:
        raise ValueError(f"Prove bank has {len(quizzes)} items; need at least {min_count}")
    hp = help_prompts or set()
    for q in quizzes:
        stem = (q.get("q") or q.get("prompt") or "").strip()
        if stem in hp:
            raise ValueError("Prove stem duplicates Help prompt")
        validate_notes_mcq(
            {
                "prompt": q.get("q") or q.get("prompt"),
                "choices": q.get("choices"),
                "answer_idx": q.get("answer_idx"),
                "explain": q.get("explain"),
            },
            notes=notes,
            label="prove",
        )
