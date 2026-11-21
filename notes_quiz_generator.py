"""Generate Help-me / Prove-it MCQs from Messer course notes (local Ollama, private cache)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.request
from typing import Any

from practice_hints import build_practice_hint
from tools.messer_notes_quiz_batch import HELP_TARGET, PROVE_MIN

CHOICE_LETTERS = "ABCD"
MAX_NOTES_CHARS = 6500
MAX_GEN_RETRIES = 3

NOTES_QUIZ_SYSTEM = """You write CompTIA Security+ study questions for one student.
Rules:
- Use ONLY facts in the course notes provided. Do not invent tools, ports, or scenarios not supported by the notes.
- Define any acronym the first time you use it in a question stem.
- Each question has exactly four answer choices (A-D). One correct answer.
- Help-me questions check understanding of terms and ideas in the notes.
- Prove-it questions are slightly harder application of the same notes (still grounded in the text).
- Non-repudiation means someone cannot credibly deny they sent or signed something. Never mark
  "ability to deny" as the correct answer for non-repudiation.
- Return JSON only, no markdown outside the JSON object.

Output shape:
{
  "help_me": [
    {"prompt": "...", "choices": ["...", "...", "...", "..."], "answer_idx": 0,
     "explain": "Correct. ... Common trap: ... Remember: ...", "hint": "..."}
  ],
  "prove_it": [
    {"prompt": "...", "choices": ["...", "...", "...", "..."], "answer_idx": 1,
     "explain": "Correct. ..."}
  ]
}
"""


def _notes_hash(notes: str) -> str:
    return hashlib.sha256((notes or "").encode("utf-8")).hexdigest()[:16]


def cache_path(work_dir, lesson_id: str):
    from pathlib import Path

    d = Path(work_dir) / "curriculum" / "notes_quizzes"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{lesson_id}.json"


def load_cached_quizzes(work_dir, lesson_id: str, notes: str) -> dict[str, Any] | None:
    """Return cached help/prove if notes hash matches."""
    p = cache_path(work_dir, lesson_id)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if data.get("notes_hash") != _notes_hash(notes):
        return None
    return data


def save_cached_quizzes(work_dir, lesson_id: str, notes: str, payload: dict[str, Any]) -> None:
    p = cache_path(work_dir, lesson_id)
    prev = load_cached_quizzes(work_dir, lesson_id, notes) or {}
    merged = {**prev, **payload, "notes_hash": _notes_hash(notes), "lesson_id": lesson_id}
    p.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")


def _call_ollama(
    prompt: str,
    *,
    system: str = NOTES_QUIZ_SYSTEM,
    max_tokens: int = 2800,
    temperature: float = 0.35,
) -> str:
    base = (os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")
    model = (os.environ.get("OLLAMA_MODEL") or "llama3.1:8b").strip()
    url = f"{base}/v1/chat/completions"
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt[:12000]},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


def _extract_json_blob(text: str) -> dict[str, Any]:
    raw = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if fence:
        raw = fence.group(1).strip()
    start = raw.find("{")
    end = raw.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("No JSON object in model response")
    return json.loads(raw[start : end + 1])


def _validate_mcq(item: dict[str, Any], label: str, *, notes: str = "") -> dict[str, Any]:
    from notes_quiz_guards import validate_notes_mcq

    prompt = (item.get("prompt") or item.get("q") or "").strip()
    choices = item.get("choices") or []
    if not prompt or len(choices) < 4:
        raise ValueError(f"{label}: need prompt and 4 choices")
    choices = [str(c).strip() for c in choices[:4]]
    if len(set(choices)) < 4:
        raise ValueError(f"{label}: choices must be distinct")
    answer_idx = int(item.get("answer_idx", 0))
    if answer_idx < 0 or answer_idx > 3:
        raise ValueError(f"{label}: answer_idx out of range")
    explain = (item.get("explain") or "Correct.").strip()
    hint = (item.get("hint") or "").strip()
    out = {
        "prompt": prompt,
        "choices": choices,
        "answer_idx": answer_idx,
        "explain": explain[:2000],
        "hint": hint[:500],
    }
    validate_notes_mcq(out, notes=notes, label=label)
    return out


def build_prompt(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    notes: str,
    mode: str = "both",
    help_prompts: list[str] | None = None,
) -> str:
    notes_trim = (notes or "").strip()[:MAX_NOTES_CHARS]
    if mode == "help":
        counts = f"Write {HELP_TARGET} help_me questions only."
    elif mode == "prove":
        avoid = ""
        if help_prompts:
            avoid = (
                " Do not reuse these Help-me stems:\n- "
                + "\n- ".join(help_prompts[:10])
            )
        counts = (
            f"Write {PROVE_MIN} prove_it questions only. "
            f"Each must be slightly harder application than Help-me.{avoid}"
        )
    else:
        counts = f"Write {HELP_TARGET} help_me and {PROVE_MIN} prove_it questions."
    return (
        f"Lesson id: {lesson_id}\n"
        f"Session title: {title}\n"
        f"CompTIA objective: {objective_ref or 'see notes'}\n\n"
        f"Course notes (only source of truth):\n{notes_trim}\n\n"
        f"{counts} Every question must be answerable from the notes above."
    )


def _help_to_practice(lesson_id: str, help_raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    practice: list[dict[str, Any]] = []
    for i, mcq in enumerate(help_raw):
        practice.append({
            "id": f"{lesson_id}:notes:help:{i:02d}",
            "prompt": mcq["prompt"],
            "choices": mcq["choices"],
            "answer_idx": mcq["answer_idx"],
            "explain": mcq["explain"],
            "correct_explain": mcq["explain"],
            "hint": mcq["hint"] or build_practice_hint(
                prompt=mcq["prompt"],
                choices=mcq["choices"],
                answer_idx=mcq["answer_idx"],
                correct_explain=mcq["explain"],
            ),
        })
    return practice


def _prove_to_quizzes(
    lesson_id: str,
    prove_raw: list[dict[str, Any]],
    *,
    help_prompts: set[str],
) -> list[dict[str, Any]]:
    quizzes: list[dict[str, Any]] = []
    for i, mcq in enumerate(prove_raw):
        if mcq["prompt"] in help_prompts:
            continue
        quizzes.append({
            "id": f"{lesson_id}:notes:prove:{len(quizzes):02d}",
            "q": mcq["prompt"],
            "choices": mcq["choices"],
            "answer_idx": mcq["answer_idx"],
            "explain": mcq["explain"],
        })
    return quizzes


def _run_generation_with_retries(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    notes: str,
    mode: str,
    help_prompts: list[str] | None = None,
) -> dict[str, Any]:
    last_err: Exception | None = None
    for attempt in range(MAX_GEN_RETRIES):
        temp = 0.35 if attempt == 0 else 0.25
        max_tokens = 1400 if mode == "help" else (2200 if mode == "prove" else 3200)
        raw = _call_ollama(
            build_prompt(
                lesson_id=lesson_id,
                title=title,
                objective_ref=objective_ref,
                notes=notes,
                mode=mode,
                help_prompts=help_prompts,
            ),
            max_tokens=max_tokens,
            temperature=temp,
        )
        try:
            return _extract_json_blob(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_err = exc
    raise ValueError(f"Model JSON failed after {MAX_GEN_RETRIES} tries: {last_err}")


def generate_notes_help(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    notes: str,
    use_cache: bool = True,
    work_dir=None,
) -> list[dict[str, Any]]:
    """Generate Help-me only (HELP_TARGET items)."""
    from messer_paths import messer_work_dir
    from notes_quiz_verify import verify_mcqs

    work = work_dir or messer_work_dir()
    notes = (notes or "").strip()
    if len(notes) < 200:
        return []

    if use_cache:
        cached = load_cached_quizzes(work, lesson_id, notes)
        if cached and cached.get("practice"):
            try:
                from notes_quiz_guards import validate_notes_mcq

                for row in cached["practice"]:
                    validate_notes_mcq({
                        "prompt": row.get("prompt"),
                        "choices": row.get("choices"),
                        "answer_idx": row.get("answer_idx"),
                        "explain": row.get("explain") or row.get("correct_explain"),
                    }, notes=notes)
                return list(cached["practice"])
            except ValueError:
                pass

    parsed = _run_generation_with_retries(
        lesson_id=lesson_id, title=title, objective_ref=objective_ref, notes=notes, mode="help",
    )
    help_raw = [
        _validate_mcq(x, "help", notes=notes)
        for x in (parsed.get("help_me") or [])[:HELP_TARGET]
    ]
    if len(help_raw) < 1:
        raise ValueError("Model returned too few help questions")
    verify_mcqs(notes, help_raw)
    practice = _help_to_practice(lesson_id, help_raw)
    save_cached_quizzes(work, lesson_id, notes, {"practice": practice})
    return practice


def generate_notes_prove(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    notes: str,
    help_prompts: set[str] | None = None,
    use_cache: bool = True,
    work_dir=None,
) -> list[dict[str, Any]]:
    """Generate Prove-it only (at least PROVE_MIN items)."""
    from messer_paths import messer_work_dir
    from notes_quiz_guards import validate_prove_bank
    from notes_quiz_verify import verify_mcqs

    work = work_dir or messer_work_dir()
    notes = (notes or "").strip()
    if len(notes) < 200:
        return []
    hp = help_prompts or set()

    if use_cache:
        cached = load_cached_quizzes(work, lesson_id, notes)
        if cached and cached.get("quizzes"):
            quizzes = list(cached["quizzes"])
            try:
                validate_prove_bank(quizzes, notes=notes, help_prompts=hp, min_count=PROVE_MIN)
                return quizzes
            except ValueError:
                pass

    hp_list = list(hp)
    last_err: Exception | None = None
    quizzes: list[dict[str, Any]] = []
    for attempt in range(MAX_GEN_RETRIES):
        try:
            parsed = _run_generation_with_retries(
                lesson_id=lesson_id,
                title=title,
                objective_ref=objective_ref,
                notes=notes,
                mode="prove",
                help_prompts=hp_list,
            )
            prove_raw = [
                _validate_mcq(x, "prove", notes=notes)
                for x in (parsed.get("prove_it") or [])[: PROVE_MIN + 3]
            ]
            quizzes = _prove_to_quizzes(lesson_id, prove_raw, help_prompts=hp)
            if len(quizzes) < PROVE_MIN:
                raise ValueError(f"After dedupe, only {len(quizzes)} prove questions; need {PROVE_MIN}")
            from notes_quiz_verify import verify_prove_bank_with_ollama

            verify_prove_bank_with_ollama(notes, quizzes)
            validate_prove_bank(quizzes, notes=notes, help_prompts=hp, min_count=PROVE_MIN)
            break
        except ValueError as exc:
            last_err = exc
            if attempt + 1 >= MAX_GEN_RETRIES:
                raise ValueError(f"Prove generation failed after {MAX_GEN_RETRIES} tries: {exc}") from exc
    save_cached_quizzes(work, lesson_id, notes, {"quizzes": quizzes})
    return quizzes


def generate_notes_quizzes(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    notes: str,
    use_cache: bool = True,
    work_dir=None,
    help_only: bool = False,
    prove_only: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Generate Help and/or Prove banks. Default: both (3 help + 5 prove).
    help_only / prove_only for batch slices.
    """
    if prove_only:
        from messer_paths import messer_work_dir

        work = work_dir or messer_work_dir()
        cached = load_cached_quizzes(work, lesson_id, notes) if use_cache else None
        hp: set[str] = set()
        if cached:
            hp = {(p.get("prompt") or "") for p in (cached.get("practice") or [])}
        prove = generate_notes_prove(
            lesson_id=lesson_id,
            title=title,
            objective_ref=objective_ref,
            notes=notes,
            help_prompts=hp,
            use_cache=use_cache,
            work_dir=work_dir,
        )
        practice = list((cached or {}).get("practice") or [])
        return practice, prove

    if help_only:
        practice = generate_notes_help(
            lesson_id=lesson_id,
            title=title,
            objective_ref=objective_ref,
            notes=notes,
            use_cache=use_cache,
            work_dir=work_dir,
        )
        return practice, []

    practice = generate_notes_help(
        lesson_id=lesson_id,
        title=title,
        objective_ref=objective_ref,
        notes=notes,
        use_cache=use_cache,
        work_dir=work_dir,
    )
    hp = {p["prompt"] for p in practice}
    prove = generate_notes_prove(
        lesson_id=lesson_id,
        title=title,
        objective_ref=objective_ref,
        notes=notes,
        help_prompts=hp,
        use_cache=use_cache,
        work_dir=work_dir,
    )
    return practice, prove
