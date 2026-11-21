"""
Private Professor Messer study layer (Jason local only).

Feature-flagged via ENABLE_MESSER_LAYER. Verbatim items live in messer_items table.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable

FetchOne = Callable[..., dict | None]
FetchAll = Callable[..., list[dict]]
Run = Callable[..., None]

_db_fetchone: FetchOne | None = None
_db_fetchall: FetchAll | None = None
_db_run: Run | None = None
_PH: str = "?"

CHOICE_LETTERS = "ABCD"


def configure(fetchone: FetchOne, fetchall: FetchAll, run: Run, ph: str) -> None:
    """Bind DB helpers from app.py."""
    global _db_fetchone, _db_fetchall, _db_run, _PH
    _db_fetchone = fetchone
    _db_fetchall = fetchall
    _db_run = run
    _PH = ph


def messer_enabled() -> bool:
    return os.environ.get("ENABLE_MESSER_LAYER", "").strip().lower() in ("1", "true", "yes")


def _require_db() -> tuple[FetchOne, FetchAll, Run, str]:
    if not _db_fetchone or not _db_fetchall or not _db_run:
        raise RuntimeError("messer_layer.configure() was not called")
    return _db_fetchone, _db_fetchall, _db_run, _PH


def upsert_item(record: dict[str, Any]) -> None:
    """Insert or replace one Messer MCQ row."""
    _, _, run, ph = _require_db()
    run(
        f"INSERT INTO messer_items "
        f"(item_id, source, objective_ref, boundry_lesson_id, messer_session, "
        f"stem, choices_json, answer_key, explain, provenance_json) "
        f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}) "
        f"ON CONFLICT(item_id) DO UPDATE SET "
        f"source=excluded.source, objective_ref=excluded.objective_ref, "
        f"boundry_lesson_id=excluded.boundry_lesson_id, messer_session=excluded.messer_session, "
        f"stem=excluded.stem, choices_json=excluded.choices_json, answer_key=excluded.answer_key, "
        f"explain=excluded.explain, provenance_json=excluded.provenance_json",
        (
            record["item_id"],
            record.get("source") or "practice_exam",
            record.get("objective_ref") or "",
            record.get("boundry_lesson_id") or "",
            record.get("messer_session") or "",
            record["stem"],
            json.dumps(record.get("choices") or [], ensure_ascii=False),
            (record.get("answer_key") or "A").upper()[:1],
            record.get("explain") or "",
            json.dumps(record.get("provenance") or {}, ensure_ascii=False),
        ),
    )


def get_item(item_id: str) -> dict[str, Any] | None:
    fo, _, _, ph = _require_db()
    row = fo(f"SELECT * FROM messer_items WHERE item_id = {ph}", (item_id,))
    if not row:
        return None
    out = dict(row)
    try:
        out["choices"] = json.loads(out.get("choices_json") or "[]")
    except json.JSONDecodeError:
        out["choices"] = []
    return out


def list_exam_ids() -> list[str]:
    _, fa, _, ph = _require_db()
    rows = fa(
        f"SELECT DISTINCT source FROM messer_items WHERE source LIKE {ph} ORDER BY source",
        ("practice_exam:%",),
    )
    out: list[str] = []
    for r in rows:
        src = r.get("source") or ""
        if src.startswith("practice_exam:"):
            out.append(src.split(":", 1)[1])
    return sorted(set(out))


def items_for_exam(exam_id: str) -> list[dict[str, Any]]:
    _, fa, _, ph = _require_db()
    rows = fa(
        f"SELECT * FROM messer_items WHERE source = {ph} ORDER BY item_id",
        (f"practice_exam:{exam_id}",),
    )
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["choices"] = json.loads(d.get("choices_json") or "[]")
        except json.JSONDecodeError:
            d["choices"] = []
        items.append(d)
    return items


def items_for_lesson(lesson_id: str, limit: int = 5) -> list[dict[str, Any]]:
    _, fa, _, ph = _require_db()
    rows = fa(
        f"SELECT * FROM messer_items WHERE boundry_lesson_id = {ph} ORDER BY item_id LIMIT {int(limit)}",
        (lesson_id,),
    )
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["choices"] = json.loads(d.get("choices_json") or "[]")
        except json.JSONDecodeError:
            d["choices"] = []
        out.append(d)
    return out


def public_mcq(item: dict[str, Any]) -> dict[str, Any]:
    """Client-safe MCQ (no answer)."""
    choices = item.get("choices") or []
    choice_map = {}
    for i, text in enumerate(choices[:4]):
        choice_map[CHOICE_LETTERS[i]] = text
    return {
        "id": item["item_id"],
        "q": item.get("stem") or "",
        "choices": choice_map,
    }


def grade_exam(exam_id: str, answers: dict[str, str]) -> dict[str, Any]:
    """Grade {item_id: letter} against Messer bank."""
    items = items_for_exam(exam_id)
    graded = []
    correct_n = 0
    for it in items:
        picked = (answers.get(it["item_id"]) or "").strip().upper()
        want = (it.get("answer_key") or "A").strip().upper()[:1]
        ok = picked == want
        if ok:
            correct_n += 1
        graded.append({
            "id": it["item_id"],
            "correct": ok,
            "picked": picked,
            "answer": want,
            "explain": it.get("explain") or "",
            "q": it.get("stem") or "",
        })
    total = len(items)
    pct = round(100 * correct_n / total) if total else 0
    return {
        "ok": True,
        "exam_id": exam_id,
        "correct": correct_n,
        "total": total,
        "pct": pct,
        "passed": pct >= 70,
        "graded": graded,
    }


def messer_session_code_from_audio(name: str) -> str | None:
    """sy0-701-0102-01-title.mp3 → 0102-01 style session key."""
    m = re.search(r"sy0-\d{3}-(\d{4})-(\d{2})", name.lower())
    if not m:
        return None
    return f"{m.group(1)}-{m.group(2)}"


def objective_from_session(session: str) -> str:
    """Map Messer 4-digit block to SY0 objective-ish ref (801 spine uses 1.1 style)."""
    if len(session) >= 2:
        dom = session[:2].lstrip("0") or "1"
        sub = session[2:4] if len(session) >= 4 else "01"
        return f"{dom}.{int(sub) if sub.isdigit() else 1}"
    return "1.1"
