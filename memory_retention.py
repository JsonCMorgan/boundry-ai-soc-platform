"""
Boundry Retention Layer (BRL) — local FSRS scheduling for Career / Training.

All review state stays in SQLite (app.db). Item IDs are stable strings; payloads
are resolved from authored banks (Sec+, Net, labs, etc.).
"""

from __future__ import annotations

import json
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

try:
    from fsrs import Card, Rating, Scheduler

    _FSRS = Scheduler()
    _HAS_FSRS = True
except ImportError:  # pragma: no cover
    Card = None  # type: ignore[misc, assignment]
    Rating = None  # type: ignore[misc, assignment]
    _FSRS = None
    _HAS_FSRS = False

FetchOne = Callable[..., dict | None]
FetchAll = Callable[..., list[dict]]
Run = Callable[..., None]

_db_fetchone: FetchOne | None = None
_db_fetchall: FetchAll | None = None
_db_run: Run | None = None
_PH: str = "?"

DEFAULT_SESSION_LIMIT = 10
ANTI_CRAM_THRESHOLD = 30
MIX_WEIGHTS = {
    "secplus": 0.35,
    "messer": 0.10,
    "net": 0.13,
    "logs": 0.13,
    "spl": 0.10,
    "kql": 0.09,
    "lab": 0.10,
}

RATING_MAP = {
    "again": 1,
    "hard": 2,
    "good": 3,
    "easy": 4,
}

FIRST_PASS_DELAY_H = 24
WRONG_DELAY_H = 0
MINI_QUIZ_DELAY_H = 72


def configure(fetchone: FetchOne, fetchall: FetchAll, run: Run, ph: str) -> None:
    """Bind DB helpers from app.py (must run once at startup)."""
    global _db_fetchone, _db_fetchall, _db_run, _PH
    _db_fetchone = fetchone
    _db_fetchall = fetchall
    _db_run = run
    _PH = ph


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _parse_iso(s: str | None) -> datetime:
    if not s:
        return _now_utc()
    raw = str(s).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        try:
            dt = datetime.strptime(raw[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return _now_utc()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def slug(text: str, max_len: int = 72) -> str:
    """Stable slug for item_id segments."""
    s = re.sub(r"[^a-zA-Z0-9]+", "_", (text or "").strip().lower()).strip("_")
    return (s[:max_len] if s else "item")


def item_id_secplus_quiz(qid: str) -> str:
    return f"secplus:q:{qid}"


def item_id_secplus_practice(lesson_id: str, practice_id: str) -> str:
    return f"secplus:practice:{lesson_id}:{practice_id}"


def item_id_secplus_term(term: str) -> str:
    return f"secplus:term:{slug(term)}"


def item_id_secplus_teach(lesson_id: str) -> str:
    return f"secplus:teach:{lesson_id}"


def item_id_secplus_mini(lesson_id: str) -> str:
    return f"secplus:mini:{lesson_id}"


def item_id_track_quiz(track: str, qid: str) -> str:
    return f"{track}:q:{qid}"


def item_id_track_practice(track: str, lesson_id: str, practice_id: str) -> str:
    return f"{track}:practice:{lesson_id}:{practice_id}"


def item_id_flashcard(track: str, idx: int) -> str:
    return f"{track}:fc:{idx}"


def item_id_lab_recall(lab: str, case_id: str) -> str:
    return f"lab:{lab}:{case_id}"


def item_id_training_scenario(name: str) -> str:
    return f"training:scenario:{slug(name)}"


def item_id_shift_tag(tag: str) -> str:
    return f"shift:tag:{slug(tag)}"


def _require_db() -> tuple[FetchOne, FetchAll, Run, str]:
    if not _db_fetchone or not _db_fetchall or not _db_run:
        raise RuntimeError("memory_retention.configure() was not called")
    return _db_fetchone, _db_fetchall, _db_run, _PH


def ensure_item(
    item_id: str,
    track: str,
    item_type: str,
    payload: dict[str, Any],
    era: str = "foundation",
) -> None:
    """Upsert catalog metadata for one retention item."""
    fo, _, run, ph = _require_db()
    existing = fo(f"SELECT item_id FROM retention_items WHERE item_id = {ph}", (item_id,))
    blob = json.dumps(payload, ensure_ascii=False)
    if existing:
        run(
            f"UPDATE retention_items SET track = {ph}, item_type = {ph}, "
            f"payload_json = {ph}, era = {ph} WHERE item_id = {ph}",
            (track, item_type, blob, era, item_id),
        )
    else:
        run(
            f"INSERT INTO retention_items (item_id, track, item_type, payload_json, era) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph})",
            (item_id, track, item_type, blob, era),
        )


def _new_fsrs_card() -> dict[str, Any]:
    if _HAS_FSRS and Card is not None:
        return Card().to_dict()
    return {"legacy": True, "interval_days": 1.0, "ease": 2.5}


def _card_from_state(state_json: str | None) -> Any:
    if _HAS_FSRS and Card is not None:
        data = json.loads(state_json or "{}")
        if data:
            return Card.from_dict(data)
        return Card()
    return json.loads(state_json or '{"legacy":true,"interval_days":1.0,"ease":2.5}')


def _schedule_after_review(state_json: str | None, rating_key: str, correct: bool) -> tuple[str, datetime]:
    """Return (new_state_json, due_at)."""
    rating_key = (rating_key or "good").lower()
    if rating_key not in RATING_MAP:
        rating_key = "good" if correct else "again"

    if _HAS_FSRS and _FSRS is not None and Rating is not None:
        card = _card_from_state(state_json)
        fsrs_rating = {
            "again": Rating.Again,
            "hard": Rating.Hard,
            "good": Rating.Good,
            "easy": Rating.Easy,
        }[rating_key]
        new_card, _log = _FSRS.review_card(card, fsrs_rating)
        due = new_card.due
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return json.dumps(new_card.to_dict()), due

    state = json.loads(state_json or "{}")
    interval = float(state.get("interval_days") or 1.0)
    ease = float(state.get("ease") or 2.5)
    if rating_key == "again":
        interval = 1.0
    elif rating_key == "hard":
        interval = max(1.0, interval * ease * 0.5)
    elif rating_key == "good":
        interval = max(1.0, interval * ease * 0.85)
    else:
        interval = max(1.0, interval * ease)
        ease = min(3.0, ease + 0.08)
    state["interval_days"] = interval
    state["ease"] = ease
    due = _now_utc() + timedelta(days=interval)
    return json.dumps(state), due


def enroll_items(
    analyst_id: int,
    specs: list[dict[str, Any]],
    *,
    source: str = "",
) -> int:
    """
    Enroll or refresh cards. Each spec: item_id, track, item_type, payload,
    optional first_due_hours, priority (wrong items → due now).
    """
    if not specs:
        return 0
    fo, _, run, ph = _require_db()
    enrolled = 0
    for spec in specs:
        item_id = spec["item_id"]
        ensure_item(
            item_id,
            spec.get("track") or "mixed",
            spec.get("item_type") or "mcq",
            spec.get("payload") or {},
            spec.get("era") or "foundation",
        )
        delay_h = spec.get("first_due_hours")
        if delay_h is None:
            delay_h = WRONG_DELAY_H if spec.get("priority") else FIRST_PASS_DELAY_H
        due = _now_utc() + timedelta(hours=float(delay_h))
        row = fo(
            f"SELECT id, due_at, reps FROM retention_cards "
            f"WHERE analyst_id = {ph} AND item_id = {ph}",
            (analyst_id, item_id),
        )
        state = _new_fsrs_card()
        if row:
            if spec.get("priority"):
                run(
                    f"UPDATE retention_cards SET due_at = {ph}, source = {ph} "
                    f"WHERE analyst_id = {ph} AND item_id = {ph}",
                    (_iso(due), source, analyst_id, item_id),
                )
                enrolled += 1
            continue
        run(
            f"INSERT INTO retention_cards "
            f"(analyst_id, item_id, due_at, state_json, reps, lapses, source) "
            f"VALUES ({ph},{ph},{ph},{ph},0,0,{ph})",
            (analyst_id, item_id, _iso(due), json.dumps(state), source),
        )
        enrolled += 1
    return enrolled


def due_count(analyst_id: int) -> int:
    fo, _, _, ph = _require_db()
    row = fo(
        f"SELECT COUNT(*) AS c FROM retention_cards "
        f"WHERE analyst_id = {ph} AND due_at <= datetime('now')",
        (analyst_id,),
    )
    return int((row or {}).get("c") or 0)


def due_backlog(analyst_id: int) -> int:
    """All cards not yet scheduled in the future (includes overdue)."""
    fo, _, _, ph = _require_db()
    row = fo(
        f"SELECT COUNT(*) AS c FROM retention_cards WHERE analyst_id = {ph}",
        (analyst_id,),
    )
    return int((row or {}).get("c") or 0)


def reviews_completed_this_week(analyst_id: int) -> int:
    fo, _, _, ph = _require_db()
    row = fo(
        f"SELECT COUNT(*) AS c FROM retention_reviews "
        f"WHERE analyst_id = {ph} AND created_at >= datetime('now', '-7 days')",
        (analyst_id,),
    )
    return int((row or {}).get("c") or 0)


def reviews_today_session(analyst_id: int) -> int:
    fo, _, _, ph = _require_db()
    row = fo(
        f"SELECT COUNT(*) AS c FROM retention_reviews "
        f"WHERE analyst_id = {ph} AND created_at >= datetime('now', 'start of day')",
        (analyst_id,),
    )
    return int((row or {}).get("c") or 0)


def due_items(
    analyst_id: int,
    limit: int = DEFAULT_SESSION_LIMIT,
    *,
    mode: str = "focus",
    track: str | None = None,
) -> list[dict[str, Any]]:
    """Return due cards with resolved display payloads."""
    _, fa, _, ph = _require_db()
    params: list[Any] = [analyst_id]
    track_sql = ""
    if mode == "focus" and track:
        track_sql = f" AND i.track = {ph}"
        params.append(track)
    rows = fa(
        f"SELECT c.id AS card_id, c.item_id, c.due_at, c.reps, c.lapses, "
        f"i.track, i.item_type, i.payload_json, i.era "
        f"FROM retention_cards c "
        f"JOIN retention_items i ON i.item_id = c.item_id "
        f"WHERE c.analyst_id = {ph} AND c.due_at <= datetime('now') "
        f"{track_sql} "
        f"ORDER BY c.due_at ASC LIMIT 200",
        tuple(params),
    )
    if mode == "mix" and rows:
        rows = _interleave_mix(rows)
    out: list[dict[str, Any]] = []
    for r in rows[:limit]:
        payload = {}
        try:
            payload = json.loads(r.get("payload_json") or "{}")
        except json.JSONDecodeError:
            payload = {}
        resolved = resolve_display(r["item_id"], payload)
        out.append({
            "card_id": r["card_id"],
            "item_id": r["item_id"],
            "track": r.get("track"),
            "item_type": r.get("item_type"),
            "due_at": r.get("due_at"),
            "reps": int(r.get("reps") or 0),
            "era": r.get("era"),
            "display": resolved,
        })
    return out


def _interleave_mix(rows: list[dict]) -> list[dict]:
    """Bucket by track and round-robin per MIX_WEIGHTS priority."""
    buckets: dict[str, list[dict]] = {}
    for r in rows:
        tr = r.get("track") or "other"
        buckets.setdefault(tr, []).append(r)
    order = sorted(buckets.keys(), key=lambda t: -MIX_WEIGHTS.get(t, 0.05))
    mixed: list[dict] = []
    idx = 0
    while len(mixed) < len(rows):
        progressed = False
        for tr in order:
            lst = buckets.get(tr) or []
            if idx < len(lst):
                mixed.append(lst[idx])
                progressed = True
        if not progressed:
            for tr in order:
                for r in buckets.get(tr, [])[idx + 1 :]:
                    mixed.append(r)
            break
        idx += 1
    return mixed


def get_item_payload(item_id: str) -> dict[str, Any]:
    """Load catalog payload for an item id."""
    fo, _, _, ph = _require_db()
    row = fo(f"SELECT payload_json FROM retention_items WHERE item_id = {ph}", (item_id,))
    if not row:
        return {}
    try:
        return json.loads(row.get("payload_json") or "{}")
    except json.JSONDecodeError:
        return {}


def resolve_display(item_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Merge catalog payload with live bank lookup when needed."""
    import secplus_learn
    import net_learn
    import spl_learn
    import kql_learn

    if item_id.startswith("secplus:q:"):
        qid = item_id.split(":", 2)[2]
        lesson_id = payload.get("lesson_id") or ""
        for q in secplus_learn.get_quiz(lesson_id) if lesson_id else []:
            if q["id"] == qid:
                return _mcq_display(q)
        return payload

    if item_id.startswith("secplus:practice:"):
        parts = item_id.split(":")
        if len(parts) >= 4:
            lesson_id, pid = parts[2], parts[3]
            for p in secplus_learn.get_practice(lesson_id):
                if p["id"] == pid:
                    return _mcq_display(p, prompt_key="prompt")
        return payload

    if item_id.startswith("secplus:term:"):
        term_key = payload.get("term") or ""
        for t in secplus_learn.all_key_terms():
            if t["term"].lower() == term_key.lower() or slug(t["term"]) == item_id.split(":")[-1]:
                return {
                    "kind": "flashcard",
                    "front": t["term"],
                    "back": f"From lesson {t['lesson_title']} ({t['objective_ref']}). Say the definition out loud, then reveal.",
                    "lesson_id": t["lesson_id"],
                }
        return {"kind": "flashcard", **payload}

    if item_id.startswith("secplus:teach:"):
        lesson_id = item_id.split(":")[-1]
        lesson = secplus_learn.get_lesson(lesson_id)
        tb = (lesson or {}).get("teach_back") or payload.get("teach_back") or payload
        beats: list[str] = []
        prompt = ""
        if isinstance(tb, dict):
            prompt = tb.get("explain_aloud") or tb.get("listener_prompt") or ""
            for d in tb.get("define_first") or []:
                if isinstance(d, dict):
                    beats.append(f"{d.get('term', '')}: {d.get('say', '')}".strip(": "))
            if tb.get("desk_one_liner"):
                beats.append(tb["desk_one_liner"])
        else:
            prompt = str(tb)
        return {
            "kind": "teach_back",
            "prompt": prompt or "Teach this lesson back in about 60 seconds.",
            "beats": beats,
            "lesson_title": (lesson or {}).get("title"),
        }

    if item_id.startswith("secplus:mini:"):
        lesson_id = payload.get("lesson_id") or item_id.split(":")[-1]
        qids = payload.get("question_ids") or []
        sub: list[dict[str, Any]] = []
        for qid in qids:
            for q in secplus_learn.get_quiz(lesson_id):
                if q["id"] == qid:
                    sub.append(_mcq_display(q))
                    break
        return {
            "kind": "mini_mcq",
            "title": payload.get("title") or "72-hour check",
            "questions": sub,
        }

    if ":practice:" in item_id:
        parts = item_id.split(":")
        if len(parts) >= 4:
            track, _, lesson_id, pid = parts[0], parts[1], parts[2], parts[3]
            learn = {"net": net_learn, "kql": kql_learn}.get(track)
            if learn:
                for p in learn.get_practice(lesson_id):
                    if p["id"] == pid:
                        return _mcq_display(p, prompt_key="prompt")
        return payload

    if ":q:" in item_id:
        track, _, qid = item_id.partition(":q:")
        if track == "net":
            for lid in net_learn.lesson_ids():
                for q in net_learn.get_quiz(lid):
                    if q["id"] == qid:
                        return _mcq_display(q)
        if track == "spl":
            for q in spl_learn.QUIZ:
                if q["id"] == qid:
                    return _mcq_display_spl(q)
        if track == "kql":
            for lid in kql_learn.lesson_ids():
                for q in kql_learn.get_quiz(lid):
                    if q["id"] == qid:
                        return _mcq_display(q)
        return payload

    if item_id.startswith("messer:"):
        import messer_layer
        if messer_layer.messer_enabled():
            it = messer_layer.get_item(item_id)
            if it:
                letters = "ABCD"
                choices = it.get("choices") or []
                choice_map = {letters[i]: choices[i] for i in range(min(4, len(choices)))}
                ans = (it.get("answer_key") or "A").upper()[:1]
                return {
                    "kind": "mcq",
                    "question_id": item_id,
                    "prompt": it.get("stem") or "",
                    "choices": choice_map,
                    "answer": ans,
                    "explain": it.get("explain") or "",
                }
        return {"kind": "mcq", **payload}

    if item_id.startswith("lab:"):
        return {"kind": "flashcard", **payload}

    if item_id.startswith("training:"):
        return {"kind": "flashcard", **payload}

    if item_id.endswith(":fc:") or ":fc:" in item_id:
        return {"kind": "flashcard", **payload}

    return payload


def _mcq_display(q: dict[str, Any], prompt_key: str = "q") -> dict[str, Any]:
    letters = "ABCD"
    choices = q.get("choices") or []
    choice_map = {letters[i]: choices[i] for i in range(min(4, len(choices)))}
    ans_idx = int(q.get("answer_idx", 0))
    return {
        "kind": "mcq",
        "question_id": q.get("id"),
        "prompt": q.get(prompt_key) or q.get("q"),
        "choices": choice_map,
        "answer": letters[ans_idx],
        "explain": q.get("explain") or "",
    }


def _mcq_display_spl(q: dict[str, Any]) -> dict[str, Any]:
    letters = "ABCD"
    choices = q.get("choices") or {}
    if isinstance(choices, dict):
        choice_map = choices
    else:
        choice_map = {letters[i]: choices[i] for i in range(min(4, len(choices)))}
    return {
        "kind": "mcq",
        "question_id": q.get("id"),
        "prompt": q.get("q"),
        "choices": choice_map,
        "answer": (q.get("answer") or "A").upper(),
        "explain": q.get("explain") or "",
    }


def grade_mcq_answer(display: dict[str, Any], picked: str) -> dict[str, Any]:
    """Local grade for review session MCQ."""
    want = (display.get("answer") or "").strip().upper()
    got = (picked or "").strip().upper()
    ok = bool(want) and got == want
    explain = display.get("explain") or ""
    if ok:
        feedback = f"Correct. {explain}".strip()
    else:
        feedback = f"Not quite. {explain}".strip()
    return {"correct": ok, "feedback": feedback, "answer": want}


def record_review(
    analyst_id: int,
    item_id: str,
    *,
    rating: str,
    correct: bool,
    ms: int | None = None,
) -> dict[str, Any]:
    """Apply FSRS update and append review log."""
    fo, _, run, ph = _require_db()
    card = fo(
        f"SELECT * FROM retention_cards WHERE analyst_id = {ph} AND item_id = {ph}",
        (analyst_id, item_id),
    )
    if not card:
        return {"ok": False, "error": "Card not found"}
    state_json, due = _schedule_after_review(card.get("state_json"), rating, correct)
    lapse_inc = 1 if rating.lower() == "again" or not correct else 0
    run(
        f"UPDATE retention_cards SET due_at = {ph}, state_json = {ph}, "
        f"reps = reps + 1, lapses = lapses + {ph} WHERE id = {ph}",
        (_iso(due), state_json, lapse_inc, card["id"]),
    )
    run(
        f"INSERT INTO retention_reviews "
        f"(analyst_id, item_id, rating, correct, ms) VALUES ({ph},{ph},{ph},{ph},{ph})",
        (
            analyst_id,
            item_id,
            RATING_MAP.get(rating.lower(), 3),
            1 if correct else 0,
            int(ms or 0),
        ),
    )
    return {"ok": True, "next_due": _iso(due)}


# ── Content adapters ─────────────────────────────────────────────────────────


def enroll_secplus_quiz_result(
    analyst_id: int,
    lesson_id: str,
    graded: list[dict[str, Any]],
    passed: bool,
) -> int:
    """After Prove-it: spaced items + wrong-priority + 72h mini quiz."""
    import secplus_learn

    lesson = secplus_learn.get_lesson(lesson_id) or {}
    specs: list[dict[str, Any]] = []
    wrong = [g for g in graded if not g.get("correct")]
    right = [g for g in graded if g.get("correct")]

    if passed:
        pick = wrong + random.sample(right, k=min(3, len(right))) if right else wrong
        pick = pick[:5]
        for g in pick:
            specs.append({
                "item_id": item_id_secplus_quiz(g["id"]),
                "track": "secplus",
                "item_type": "mcq",
                "payload": {"lesson_id": lesson_id, "question_id": g["id"]},
            })
        teach = lesson.get("teach_back")
        if teach:
            specs.append({
                "item_id": item_id_secplus_teach(lesson_id),
                "track": "secplus",
                "item_type": "teach_back",
                "payload": {"lesson_id": lesson_id, "teach_back": teach},
            })
        bank = secplus_learn.get_quiz(lesson_id)
        if len(bank) >= 3:
            mini_ids = random.sample([q["id"] for q in bank], k=3)
            specs.append({
                "item_id": item_id_secplus_mini(lesson_id),
                "track": "secplus",
                "item_type": "mini_mcq",
                "payload": {
                    "lesson_id": lesson_id,
                    "title": f"72h check: {lesson.get('title', lesson_id)}",
                    "question_ids": mini_ids,
                },
                "first_due_hours": MINI_QUIZ_DELAY_H,
            })
    else:
        for g in wrong:
            specs.append({
                "item_id": item_id_secplus_quiz(g["id"]),
                "track": "secplus",
                "item_type": "mcq",
                "payload": {"lesson_id": lesson_id, "question_id": g["id"]},
                "priority": True,
            })

    return enroll_items(analyst_id, specs, source=f"secplus_prove:{lesson_id}")


def enroll_secplus_practice_wrong(
    analyst_id: int,
    lesson_id: str,
    practice_id: str,
) -> int:
    import secplus_learn

    item = next((p for p in secplus_learn.get_practice(lesson_id) if p["id"] == practice_id), None)
    if not item:
        return 0
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_secplus_practice(lesson_id, practice_id),
            "track": "secplus",
            "item_type": "mcq",
            "payload": {"lesson_id": lesson_id, "practice_id": practice_id},
            "priority": True,
        }],
        source=f"secplus_help:{lesson_id}",
    )


def enroll_secplus_term(analyst_id: int, term: str) -> int:
    import secplus_learn

    meta = next((t for t in secplus_learn.all_key_terms() if t["term"].lower() == term.lower()), None)
    if not meta:
        return 0
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_secplus_term(term),
            "track": "secplus",
            "item_type": "flashcard",
            "payload": {"term": meta["term"], "lesson_id": meta["lesson_id"]},
        }],
        source="secplus_terms",
    )


def enroll_secplus_teach_back(analyst_id: int, lesson_id: str) -> int:
    import secplus_learn

    lesson = secplus_learn.get_lesson(lesson_id)
    if not lesson or not lesson.get("teach_back"):
        return 0
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_secplus_teach(lesson_id),
            "track": "secplus",
            "item_type": "teach_back",
            "payload": {"lesson_id": lesson_id},
        }],
        source="secplus_teach_back",
    )


def enroll_track_quiz_result(
    analyst_id: int,
    track: str,
    lesson_id: str | None,
    graded: list[dict[str, Any]],
    passed: bool,
) -> int:
    specs: list[dict[str, Any]] = []
    wrong = [g for g in graded if not g.get("correct")]
    right = [g for g in graded if g.get("correct")]
    if passed:
        pick = (wrong + random.sample(right, k=min(2, len(right)))) if right else wrong
        for g in pick[:4]:
            specs.append({
                "item_id": item_id_track_quiz(track, g["id"]),
                "track": track,
                "item_type": "mcq",
                "payload": {"lesson_id": lesson_id, "question_id": g["id"]},
            })
    else:
        for g in wrong:
            specs.append({
                "item_id": item_id_track_quiz(track, g["id"]),
                "track": track,
                "item_type": "mcq",
                "payload": {"lesson_id": lesson_id, "question_id": g["id"]},
                "priority": True,
            })
    return enroll_items(analyst_id, specs, source=f"{track}_prove")


def enroll_track_practice_wrong(
    analyst_id: int,
    track: str,
    lesson_id: str,
    practice_id: str,
) -> int:
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_track_practice(track, lesson_id, practice_id),
            "track": track,
            "item_type": "mcq",
            "payload": {"lesson_id": lesson_id, "practice_id": practice_id},
            "priority": True,
        }],
        source=f"{track}_help",
    )


def enroll_hub_flashcards(analyst_id: int, track: str, cards: list[dict[str, str]]) -> int:
    specs = []
    for idx, fc in enumerate(cards):
        specs.append({
            "item_id": item_id_flashcard(track, idx),
            "track": track,
            "item_type": "flashcard",
            "payload": {"front": fc.get("front", ""), "back": fc.get("back", "")},
        })
    return enroll_items(analyst_id, specs, source=f"{track}_flashcards")


def enroll_lab_case_pass(analyst_id: int, lab: str, case_id: str, teach: str, title: str) -> int:
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_lab_recall(lab, case_id),
            "track": "lab",
            "item_type": "flashcard",
            "payload": {
                "front": f"Cold recall: {title}",
                "back": teach,
                "case_id": case_id,
            },
            "era": "foundation",
        }],
        source=f"lab:{lab}",
    )


def enroll_training_scenario(analyst_id: int, scenario_name: str, label: str) -> int:
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_training_scenario(scenario_name),
            "track": "training",
            "item_type": "flashcard",
            "payload": {
                "front": f"Re-run scenario: {label}",
                "back": "Schedule a full re-challenge in Training. Same scenario id, fresh attempt.",
                "scenario_name": scenario_name,
                "href": "/training",
            },
            "first_due_hours": 72,
        }],
        source="training_scenario",
    )


def enroll_messer_exam_result(
    analyst_id: int,
    graded: list[dict[str, Any]],
    passed: bool,
) -> int:
    """Enroll Messer practice exam items into Daily Review."""
    specs: list[dict[str, Any]] = []
    wrong = [g for g in graded if not g.get("correct")]
    right = [g for g in graded if g.get("correct")]
    if passed:
        pick = wrong + random.sample(right, k=min(3, len(right))) if right else wrong
        for g in pick[:8]:
            specs.append({
                "item_id": g["id"],
                "track": "messer",
                "item_type": "mcq",
                "payload": {"question_id": g["id"]},
            })
    else:
        for g in wrong:
            specs.append({
                "item_id": g["id"],
                "track": "messer",
                "item_type": "mcq",
                "payload": {"question_id": g["id"]},
                "priority": True,
            })
    return enroll_items(analyst_id, specs, source="messer_exam")


def enroll_messer_lesson_supplement(analyst_id: int, lesson_id: str, limit: int = 3) -> int:
    """Optional post-prove Messer items for a lesson."""
    import messer_layer
    if not messer_layer.messer_enabled():
        return 0
    items = messer_layer.items_for_lesson(lesson_id, limit=limit)
    specs = [{
        "item_id": it["item_id"],
        "track": "messer",
        "item_type": "mcq",
        "payload": {"question_id": it["item_id"], "lesson_id": lesson_id},
    } for it in items]
    return enroll_items(analyst_id, specs, source=f"messer_lesson:{lesson_id}")


def enroll_shift_followup(analyst_id: int, mitre_tag: str) -> int:
    if not mitre_tag:
        return 0
    return enroll_items(
        analyst_id,
        [{
            "item_id": item_id_shift_tag(mitre_tag),
            "track": "shift",
            "item_type": "flashcard",
            "payload": {
                "front": f"Shift follow-up: {mitre_tag}",
                "back": "Name one alert pattern and disposition you would use for this technique on shift.",
            },
            "first_due_hours": 48,
        }],
        source="shift_complete",
    )


def retention_streak_days(analyst_id: int) -> int:
    """Consecutive calendar days (UTC) with at least one retention review."""
    _, fa, _, ph = _require_db()
    rows = fa(
        f"SELECT DISTINCT date(created_at) AS d FROM retention_reviews "
        f"WHERE analyst_id = {ph} ORDER BY d DESC LIMIT 400",
        (analyst_id,),
    )
    if not rows:
        return 0
    streak = 0
    expect = _now_utc().date()
    for row in rows:
        raw = row.get("d")
        if not raw:
            continue
        try:
            day = datetime.strptime(str(raw)[:10], "%Y-%m-%d").date()
        except ValueError:
            continue
        if day == expect:
            streak += 1
            expect = expect - timedelta(days=1)
        elif day == expect - timedelta(days=1) and streak == 0:
            # Allow starting streak from yesterday if none today yet
            expect = day
            streak += 1
            expect = expect - timedelta(days=1)
        else:
            break
    return streak


def export_reviews_csv(analyst_id: int, limit: int = 5000) -> str:
    """Local-only review log export for self-study analysis."""
    _, fa, _, ph = _require_db()
    rows = fa(
        f"SELECT item_id, rating, correct, ms, created_at FROM retention_reviews "
        f"WHERE analyst_id = {ph} ORDER BY id DESC LIMIT {int(limit)}",
        (analyst_id,),
    )
    lines = ["item_id,rating,correct,ms,created_at"]
    for r in rows:
        lines.append(
            f"{r.get('item_id','')},{r.get('rating','')},{r.get('correct','')},"
            f"{r.get('ms','')},{r.get('created_at','')}"
        )
    return "\n".join(lines) + "\n"


def track_due_count(analyst_id: int, track: str) -> int:
    fo, _, _, ph = _require_db()
    row = fo(
        f"SELECT COUNT(*) AS c FROM retention_cards c "
        f"JOIN retention_items i ON i.item_id = c.item_id "
        f"WHERE c.analyst_id = {ph} AND i.track = {ph} AND c.due_at <= datetime('now')",
        (analyst_id, track),
    )
    return int((row or {}).get("c") or 0)
