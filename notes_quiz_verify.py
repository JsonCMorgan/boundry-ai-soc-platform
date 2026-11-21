"""Local Ollama verifier for notes-grounded MCQs."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any

VERIFY_SYSTEM = """You verify CompTIA Security+ study MCQs against course notes only.
Return JSON only: {"pass": true} or {"pass": false, "reason": "...", "better_index": 0|1|2|3|null}.
Fail only if the marked correct answer clearly contradicts the notes or inverts negation
(e.g. non-repudiation as ability to deny). Pass if the answer is reasonably supported by the notes,
even if wording differs slightly.
When fail is true, set better_index to the 0-based index of the best choice if one choice clearly
matches the notes; otherwise null."""


def skip_verify() -> bool:
    return os.environ.get("MESSER_QUIZ_SKIP_VERIFY", "").strip().lower() in ("1", "true", "yes")


def _parse_verify_json(raw: str) -> dict[str, Any]:
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0:
        return {"pass": False, "reason": "Verifier returned no JSON"}
    data = json.loads(raw[start : end + 1])
    if not isinstance(data, dict):
        return {"pass": False, "reason": "Verifier JSON was not an object"}
    return data


def verify_mcq_detail(notes: str, mcq: dict[str, Any]) -> dict[str, Any]:
    """Ollama verify one MCQ; returns pass, reason, optional better_index."""
    if skip_verify():
        return {"pass": True, "reason": "skip_verify", "better_index": None}
    from notes_quiz_generator import _call_ollama

    stem = mcq.get("prompt") or mcq.get("q") or ""
    choices = mcq.get("choices") or []
    idx = int(mcq.get("answer_idx", 0))
    correct = choices[idx] if 0 <= idx < len(choices) else ""
    user = (
        f"Notes:\n{(notes or '')[:6000]}\n\n"
        f"Question: {stem}\n"
        f"Choices: A={choices[0] if len(choices)>0 else ''} B={choices[1] if len(choices)>1 else ''} "
        f"C={choices[2] if len(choices)>2 else ''} D={choices[3] if len(choices)>3 else ''}\n"
        f"Marked correct index: {idx} ({correct})\n"
        f"Explain: {mcq.get('explain') or ''}\n"
        "Does the marked correct answer match the notes?"
    )
    raw = _call_ollama(user, system=VERIFY_SYSTEM, max_tokens=220, temperature=0.1)
    data = _parse_verify_json(raw)
    if not data.get("pass") and data.get("reason") == "Verifier returned no JSON":
        raw = _call_ollama(user, system=VERIFY_SYSTEM, max_tokens=220, temperature=0.05)
        data = _parse_verify_json(raw)
    better = data.get("better_index")
    if better is not None and better != "":
        try:
            better = int(better)
        except (TypeError, ValueError):
            better = None
    else:
        better = None
    return {
        "pass": bool(data.get("pass")),
        "reason": str(data.get("reason") or "").strip(),
        "better_index": better,
    }


def verify_mcq_with_ollama(notes: str, mcq: dict[str, Any]) -> bool:
    """Return True if Ollama confirms the MCQ matches notes."""
    return verify_mcq_detail(notes, mcq).get("pass") is True


def verify_prove_bank_with_ollama(notes: str, quizzes: list[dict[str, Any]]) -> None:
    """One Ollama pass for the whole Prove bank (faster, consistent)."""
    if skip_verify() or not quizzes:
        return
    from notes_quiz_generator import _call_ollama

    lines = []
    for i, q in enumerate(quizzes):
        ch = q.get("choices") or []
        idx = int(q.get("answer_idx", 0))
        lines.append(
            f"{i + 1}. {q.get('q') or q.get('prompt')}\n"
            f"   Correct ({idx}): {ch[idx] if idx < len(ch) else '?'}\n"
            f"   Explain: {(q.get('explain') or '')[:200]}"
        )
    user = (
        f"Notes:\n{(notes or '')[:6000]}\n\n"
        f"Prove-it bank ({len(quizzes)} questions):\n"
        + "\n".join(lines)
        + "\n\nDo all marked correct answers match the notes? JSON only."
    )
    raw = _call_ollama(user, system=VERIFY_SYSTEM, max_tokens=200, temperature=0.1)
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0:
        raise ValueError("Verifier returned no JSON")
    data = json.loads(raw[start : end + 1])
    if not data.get("pass"):
        raise ValueError(data.get("reason") or "Ollama verifier rejected Prove bank")


def verify_mcqs(notes: str, mcqs: list[dict[str, Any]]) -> None:
    """Raise ValueError if MCQs fail verification."""
    from tools.messer_notes_quiz_batch import PROVE_MIN

    if len(mcqs) >= PROVE_MIN:
        verify_prove_bank_with_ollama(notes, [
            {
                "q": m.get("prompt") or m.get("q"),
                "choices": m.get("choices"),
                "answer_idx": m.get("answer_idx"),
                "explain": m.get("explain"),
            }
            for m in mcqs
        ])
        return
    for mcq in mcqs:
        if not verify_mcq_with_ollama(notes, mcq):
            stem = (mcq.get("prompt") or mcq.get("q") or "")[:80]
            raise ValueError(f"Ollama verifier rejected MCQ: {stem}")
