"""Shared helpers for Messer note-grounded Help batch (resume, log, atomic save)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NOTES_MIN_LEN = 200
HELP_TARGET = 3
PROVE_MIN = 5
QUIZ_SOURCE_HYBRID = "hybrid_notes_help_notes_prove"
QUIZ_SOURCE_FULL_NOTES = "notes_ollama"
BATCH_LOG_NAME = "notes_quiz_batch.log"


def batch_log_path(work_dir: Path) -> Path:
    return work_dir / "curriculum" / BATCH_LOG_NAME


def course_notes_body(lesson: dict[str, Any]) -> str:
    for sec in lesson.get("sections") or []:
        if (sec.get("heading") or "").lower() == "course notes":
            return (sec.get("body") or "").strip()
    return ""


def study_source_body(lesson: dict[str, Any]) -> str:
    """Course notes plus transcript when notes are thin (Prove/Help generation source)."""
    notes = course_notes_body(lesson)
    transcript = ""
    for sec in lesson.get("sections") or []:
        if (sec.get("heading") or "").lower() == "transcript":
            transcript = (sec.get("body") or "").strip()
            break
    if len(notes) >= NOTES_MIN_LEN:
        return notes
    if transcript:
        return f"{notes}\n\nTranscript:\n{transcript}".strip()
    return notes


def notes_eligible(lesson: dict[str, Any]) -> tuple[bool, str]:
    """Return (eligible, reason) where reason is ok | thin | missing."""
    body = study_source_body(lesson)
    if not body:
        return False, "missing"
    if len(body) < NOTES_MIN_LEN:
        return False, "thin"
    return True, "ok"


def has_notes_help(practice: list[dict[str, Any]] | None) -> bool:
    for p in practice or []:
        pid = (p.get("id") or "").strip()
        if ":notes:help:" in pid:
            return True
    return False


def count_notes_prove(quizzes: list[dict[str, Any]] | None) -> int:
    n = 0
    for q in quizzes or []:
        if ":notes:prove:" in (q.get("id") or ""):
            n += 1
    return n


def has_notes_prove(quizzes: list[dict[str, Any]] | None) -> bool:
    return count_notes_prove(quizzes) >= PROVE_MIN


def append_batch_log(
    work_dir: Path,
    *,
    lesson_id: str,
    status: str,
    help_count: int = 0,
    prove_count: int = 0,
    error: str = "",
) -> None:
    p = batch_log_path(work_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "lesson_id": lesson_id,
        "status": status,
        "help_count": help_count,
        "prove_count": prove_count,
        "error": (error or "")[:500],
    }
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def failed_lesson_ids_from_log(work_dir: Path) -> list[str]:
    p = batch_log_path(work_dir)
    if not p.is_file():
        return []
    last: dict[str, str] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        lid = row.get("lesson_id") or ""
        if lid:
            last[lid] = row.get("status") or ""
    return [lid for lid, st in last.items() if st == "fail"]


def write_curriculum_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def apply_lesson_help_to_payload(
    data: dict[str, Any],
    lesson: dict[str, Any],
    help_items: list[dict[str, Any]],
) -> None:
    """Patch Help-me practice and lesson flags."""
    lid = lesson["id"]
    data.setdefault("practice", {})[lid] = help_items
    lesson["has_help_me"] = bool(help_items)
    data["quiz_source"] = QUIZ_SOURCE_HYBRID


def apply_lesson_prove_to_payload(
    data: dict[str, Any],
    lesson: dict[str, Any],
    prove_items: list[dict[str, Any]],
) -> int:
    """Patch Prove-it bank; has_prove requires PROVE_MIN notes prove items."""
    lid = lesson["id"]
    data.setdefault("quizzes", {})[lid] = prove_items
    lesson["has_prove"] = has_notes_prove(prove_items)
    data["quiz_source"] = QUIZ_SOURCE_HYBRID
    return len(prove_items)
