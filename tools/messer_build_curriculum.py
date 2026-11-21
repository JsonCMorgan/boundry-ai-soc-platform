#!/usr/bin/env python3
"""Build private SY0-701 curriculum (121 Messer sessions) under content/private/messer/curriculum/."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_catalog import load_session_map  # noqa: E402
from messer_paths import messer_work_dir  # noqa: E402

CHOICE_LETTERS = "ABCD"

DOMAINS_701 = [
    {
        "id": "d1_concepts",
        "order": 1,
        "weight": 12,
        "title": "General Security Concepts",
        "short": "Controls, CIA, crypto basics",
        "color": "#2dd4bf",
        "goal": "Domain 1 (12% on SY0-701).",
        "hub_note": "Messer session spine — course notes + practice exams.",
        "objectives": ["1.x"],
    },
    {
        "id": "d2_threats",
        "order": 2,
        "weight": 22,
        "title": "Threats, Vulnerabilities, and Mitigations",
        "short": "Threats, vulns, malware, IOCs",
        "color": "#ff8c00",
        "goal": "Domain 2 (22% on SY0-701).",
        "hub_note": "Largest domain on 701.",
        "objectives": ["2.x"],
    },
    {
        "id": "d3_architecture",
        "order": 3,
        "weight": 18,
        "title": "Security Architecture",
        "short": "Cloud, network, data, resilience",
        "color": "#a78bfa",
        "goal": "Domain 3 (18% on SY0-701).",
        "hub_note": "Architecture and data protection.",
        "objectives": ["3.x"],
    },
    {
        "id": "d4_operations",
        "order": 4,
        "weight": 28,
        "title": "Security Operations",
        "short": "Ops, IAM, IR, tooling",
        "color": "#00ff88",
        "goal": "Domain 4 (28% on SY0-701).",
        "hub_note": "Heaviest domain on 701.",
        "objectives": ["4.x"],
    },
    {
        "id": "d5_oversight",
        "order": 5,
        "weight": 20,
        "title": "Security Program Management and Oversight",
        "short": "Governance, risk, compliance",
        "color": "#f472b6",
        "goal": "Domain 5 (20% on SY0-701).",
        "hub_note": "Program and oversight.",
        "objectives": ["5.x"],
    },
]

DOMAIN_BY_ID = {d["id"]: d for d in DOMAINS_701}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


_BULLET_START = re.compile(r"^[\u2022\u2023\ufffd•\-]\s*(.+)$")
_SKIP_TERM_START = (
    "many ", "how ", "this ", "you ", "the ", "after ", "consider ", "make ",
    "increase ", "find ", "apply ", "enable ", "review ", "collect ", "store ",
    "authenticate ", "system ", "during ", "important ", "critical ",
)


def _extract_key_terms(body: str, max_terms: int = 18) -> list[str]:
    """Top-level Messer note bullets and short section labels."""
    terms: list[str] = []
    seen: set[str] = set()
    for raw in (body or "").splitlines():
        line = raw.strip()
        if not line or "professormesser" in line.lower() or line.startswith("http"):
            continue
        if raw.startswith("\t") or raw.startswith("    "):
            continue
        m = _BULLET_START.match(line)
        if m:
            term = re.sub(r"\s+", " ", m.group(1).strip())
            if len(term) < 3 or len(term) > 52:
                continue
            low = term.lower()
            if any(low.startswith(p) for p in _SKIP_TERM_START):
                continue
            if " are " in low or " is " in low or " and " in low and len(term) > 28:
                continue
            if term.endswith(",") or ("," in term and len(term) > 22):
                continue
            if low in seen:
                continue
            seen.add(low)
            terms.append(term)
            continue
        if re.match(r"^[A-Za-z][A-Za-z0-9 \-/]{2,44}$", line):
            low = line.lower()
            if low in ("security controls", "control categories") or "control" in low or "types" in low:
                if low not in seen:
                    seen.add(low)
                    terms.append(line)
    return terms[:max_terms]


def _session_lesson_id(messer_session: str) -> str:
    return "ms_" + messer_session.replace("-", "_")


def _transcript_for_session(sess: dict, work: Path) -> str:
    """Sidecar or extracted transcript text for this session's audio/video."""
    transcripts_dir = work / "transcripts"
    for rel in (sess.get("audio_paths") or []) + (sess.get("video_paths") or []):
        stem = Path(rel).stem
        for name in (f"{stem}.txt", f"{stem}.vtt", f"{stem}.srt"):
            p = transcripts_dir / name
            if p.is_file() and p.suffix.lower() == ".txt":
                return p.read_text(encoding="utf-8", errors="replace")[:12000]
            if p.is_file():
                return p.read_text(encoding="utf-8", errors="replace")[:12000]
    return ""


def _load_notes_text(work: Path) -> str:
    extracted = work / "extracted"
    for p in extracted.glob("*.json") if extracted.is_dir() else []:
        if "course-notes" in p.name.lower():
            data = json.loads(p.read_text(encoding="utf-8"))
            return "\n".join(pg.get("text") or "" for pg in data.get("pages") or [])
    return ""


def _index_notes_sections(full_text: str) -> list[dict]:
    full_text = re.sub(r"\x08", " ", full_text)
    chunks = re.split(r"\n(?=\d\.\d\s*-)", full_text)
    out: list[dict] = []
    for chunk in chunks:
        m = re.match(r"(\d\.\d)\s*-\s*([^\n]+)", chunk)
        if not m:
            continue
        ref = m.group(1)
        title = m.group(2).strip()
        body = chunk[m.end() :].strip()
        body = re.sub(r"©\s*\d{4}.*", "", body, flags=re.I)
        body = re.sub(r"Professor Messer.*?Course Notes.*?\n", "", body, flags=re.I)
        if len(body) < 40:
            continue
        out.append({"ref": ref, "title": title, "body": body[:8000]})
    return out


def _match_notes_section(session: dict, sections: list[dict]) -> dict | None:
    obj = session.get("objective_ref") or ""
    title_hint = _norm(session.get("messer_title") or "")
    words = [w for w in title_hint.split() if len(w) > 3 and w not in ("sy0", "701")]
    candidates = [s for s in sections if s["ref"] == obj or s["ref"].startswith(obj.split(".")[0] + ".")]
    if not candidates:
        candidates = sections
    best = None
    best_score = -1
    for s in candidates:
        st = _norm(s["title"])
        score = sum(1 for w in words if w in st)
        if st in title_hint or title_hint in st:
            score += 5
        if score > best_score:
            best_score = score
            best = s
    return best


def _load_messer_items() -> list[dict]:
    import app as app_module

    rows = app_module.db_fetchall("SELECT * FROM messer_items ORDER BY item_id")
    items = []
    for r in rows:
        d = dict(r)
        try:
            d["choices"] = json.loads(d.get("choices_json") or "[]")
        except json.JSONDecodeError:
            d["choices"] = []
        items.append(d)
    return items


def _objective_from_item(item: dict) -> str:
    obj = (item.get("objective_ref") or "").strip()
    m = re.search(r"Objective\s+(\d\.\d)", obj, re.I)
    return m.group(1) if m else ""


def _letter_to_idx(letter: str) -> int:
    key = (letter or "A").strip().upper()[:1]
    return CHOICE_LETTERS.index(key) if key in CHOICE_LETTERS else 0


def _mcq_to_practice(item: dict, suffix: str) -> dict:
    prov = item.get("provenance") or item.get("provenance_json") or {}
    if isinstance(prov, str):
        try:
            prov = json.loads(prov)
        except Exception:
            prov = {}
    correct_explain = (prov.get("correct_explain") or "").strip()
    more_info = (prov.get("more_info") or "").strip()
    choices = (item.get("choices") or [])[:4]
    answer_idx = _letter_to_idx(item.get("answer_key") or "A")
    from practice_hints import build_practice_hint

    return {
        "id": f"{item['item_id']}:help:{suffix}",
        "prompt": item.get("stem") or "",
        "choices": choices,
        "answer_idx": answer_idx,
        "explain": (item.get("explain") or "Correct.")[:2000],
        "correct_explain": correct_explain[:2000],
        "more_info": more_info[:800],
        "hint": build_practice_hint(
            prompt=item.get("stem") or "",
            choices=choices,
            answer_idx=answer_idx,
            correct_explain=correct_explain,
            more_info=more_info,
        ),
    }


def _mcq_to_quiz(item: dict) -> dict:
    return {
        "id": item["item_id"],
        "q": item.get("stem") or "",
        "choices": (item.get("choices") or [])[:4],
        "answer_idx": _letter_to_idx(item.get("answer_key") or "A"),
        "explain": (item.get("explain") or "Correct.")[:2000],
    }


def _assign_items_to_sessions(sessions: list[dict], items: list[dict]) -> dict[str, list[dict]]:
    by_obj: dict[str, list[dict]] = {}
    for it in items:
        obj = _objective_from_item(it)
        if obj:
            by_obj.setdefault(obj, []).append(it)
    per_session: dict[str, list[dict]] = {}
    for obj, pool in by_obj.items():
        sess = [s for s in sessions if s.get("objective_ref") == obj]
        if not sess:
            continue
        n = len(sess)
        for i, s in enumerate(sess):
            lid = _session_lesson_id(s["messer_session"])
            chunk = pool[i::n]
            if not chunk and pool:
                # More sessions than imported MCQs for this objective — reuse with offset.
                chunk = [pool[i % len(pool)]]
            per_session[lid] = chunk
    return per_session


def _split_help_prove(
    session_pool: list[dict],
    *,
    help_cap: int = 3,
    prove_cap: int = 8,
) -> tuple[list[dict], list[dict]]:
    """
    Split this session's assigned MCQs only (no borrowing from sibling videos).

    Avoids Prove on lesson B repeating Help or Prove from lesson A on the same objective.
    """
    pool = list(session_pool)
    if not pool:
        return [], []
    if len(pool) == 1:
        return pool, []

    # First chunk → Help me; remainder → Prove it (same session bank, no overlap).
    help_n = min(help_cap, max(1, (len(pool) + 1) // 2))
    help_raw = pool[:help_n]
    help_ids = {it["item_id"] for it in help_raw}
    prove_raw = [it for it in pool[help_n:] if it["item_id"] not in help_ids]

    if not prove_raw and len(pool) > 1:
        prove_raw = [pool[-1]] if pool[-1]["item_id"] not in help_ids else []

    return help_raw, prove_raw[:prove_cap]


def build() -> dict:
    work = messer_work_dir()
    sessions = load_session_map()
    if not sessions:
        raise SystemExit("No session_map.json — run messer_build_session_map.py first")
    notes_text = _load_notes_text(work)
    note_sections = _index_notes_sections(notes_text) if notes_text else []
    items = _load_messer_items()
    items_by_lesson = _assign_items_to_sessions(sessions, items)

    lessons: list[dict] = []
    practice: dict[str, list] = {}
    quizzes: dict[str, list] = {}

    for order, sess in enumerate(sessions, start=1):
        lid = _session_lesson_id(sess["messer_session"])
        domain_id = sess.get("domain_id") or "d1_concepts"
        dom = DOMAIN_BY_ID.get(domain_id, DOMAINS_701[0])
        sec = _match_notes_section(sess, note_sections)
        title = sec["title"] if sec else (sess.get("messer_title") or lid)
        notes_body = sec["body"] if sec else "(No notes extract for this session yet.)"
        key_terms = _extract_key_terms(notes_body) if sec else []
        transcript = _transcript_for_session(sess, work)
        sections: list[dict[str, str]] = [
            {
                "heading": "Session",
                "body": (
                    f"Session {sess.get('messer_session')} · Objective {sess.get('objective_ref') or '—'}.\n"
                    "Course notes match this Messer video session. Use the transcript when you have it for commute review."
                ),
            },
            {"heading": "Course notes", "body": notes_body},
        ]
        if transcript.strip():
            sections.append({"heading": "Transcript", "body": transcript.strip()})
        lesson = {
            "id": lid,
            "order": order,
            "domain_id": domain_id,
            "domain_order": dom["order"],
            "domain_title": dom["title"],
            "domain_color": dom["color"],
            "domain_weight": dom["weight"],
            "objective_ref": sess.get("objective_ref") or "",
            "legacy_ref": sess.get("objective_ref") or "",
            "objective_exam": "SY0-701",
            "title": title[:120],
            "minutes": 15,
            "goal": f"Review {title[:80]} (notes + video session {sess.get('messer_session')}).",
            "key_terms": key_terms,
            "sections": sections,
            "teach_back": {
                "prompt": f"In 60 seconds, explain {title} aloud using the notes.",
                "exam_trap": "Watch for answers that confuse control type with tool or policy layer.",
            },
            "has_pbq": False,
            "has_help_me": False,
            "has_prove": False,
            "job_ctas": [],
            "messer_session": sess.get("messer_session"),
            "audio_paths": sess.get("audio_paths") or [],
            "video_paths": sess.get("video_paths") or [],
        }
        lessons.append(lesson)

        pool = items_by_lesson.get(lid) or []
        help_raw, prove_raw = _split_help_prove(pool)
        help_items = [_mcq_to_practice(it, str(i)) for i, it in enumerate(help_raw)]
        prove_items = [_mcq_to_quiz(it) for it in prove_raw]
        practice[lid] = help_items
        quizzes[lid] = []
        lesson["has_help_me"] = bool(help_items)
        lesson["has_prove"] = False

    practice_exam_fallback = dict(practice)

    return {
        "version": "SY0-701",
        "source": "messer_private",
        "session_count": len(lessons),
        "domains": DOMAINS_701,
        "lessons": lessons,
        "practice": practice,
        "quizzes": quizzes,
        "practice_exam_fallback": practice_exam_fallback,
        "pbqs": {},
    }


def _apply_notes_quizzes(payload: dict, *, lesson_filter: str = "", limit: int = 0) -> int:
    """Optional: Ollama Help + Prove (5 min) from course notes."""
    import os

    if os.environ.get("MESSER_QUIZ_FROM_NOTES", "").strip().lower() not in ("1", "true", "yes"):
        return 0
    from notes_quiz_generator import generate_notes_help, generate_notes_prove
    from tools.messer_notes_quiz_batch import (
        PROVE_MIN,
        QUIZ_SOURCE_HYBRID,
        apply_lesson_help_to_payload,
        apply_lesson_prove_to_payload,
        study_source_body,
    )

    n = 0
    for L in payload.get("lessons") or []:
        if lesson_filter and L["id"] != lesson_filter:
            continue
        if limit and n >= limit:
            break
        lid = L["id"]
        notes = study_source_body(L)
        if len(notes.strip()) < 200:
            continue
        try:
            help_items = generate_notes_help(
                lesson_id=lid,
                title=L.get("title") or lid,
                objective_ref=L.get("objective_ref") or "",
                notes=notes,
            )
            apply_lesson_help_to_payload(payload, L, help_items)
            hp = {p["prompt"] for p in help_items}
            prove_items = generate_notes_prove(
                lesson_id=lid,
                title=L.get("title") or lid,
                objective_ref=L.get("objective_ref") or "",
                notes=notes,
                help_prompts=hp,
            )
            if len(prove_items) < PROVE_MIN:
                raise ValueError(f"prove count {len(prove_items)}")
            apply_lesson_prove_to_payload(payload, L, prove_items)
            payload["quiz_source"] = QUIZ_SOURCE_HYBRID
            n += 1
            print(f"  notes-quiz {lid}: help={len(help_items)} prove={len(prove_items)}")
        except Exception as exc:
            print(f"  notes-quiz SKIP {lid}: {exc}")
    return n


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Build Messer 701 curriculum JSON")
    parser.add_argument(
        "--from-notes",
        action="store_true",
        help="Generate Help + Prove (5 min) from course notes (Ollama)",
    )
    parser.add_argument("--lesson", type=str, default="", help="With --from-notes, only this lesson id")
    parser.add_argument("--notes-limit", type=int, default=0, help="Max lessons for --from-notes (0=all)")
    args, _ = parser.parse_known_args()
    if args.from_notes:
        import os

        os.environ["MESSER_QUIZ_FROM_NOTES"] = "1"

    payload = build()
    if args.from_notes or __import__("os").environ.get("MESSER_QUIZ_FROM_NOTES"):
        print("Generating note-grounded quizzes (local Ollama)...")
        _apply_notes_quizzes(
            payload,
            lesson_filter=args.lesson.strip(),
            limit=args.notes_limit,
        )
        from tools.messer_notes_quiz_batch import QUIZ_SOURCE_HYBRID

        payload["quiz_source"] = QUIZ_SOURCE_HYBRID
    out_dir = messer_work_dir() / "curriculum"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "701_curriculum.json"
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    with_practice = sum(1 for v in payload["practice"].values() if v)
    with_quiz = sum(1 for v in payload["quizzes"].values() if v)
    print(f"Wrote {out_path} — {payload['session_count']} lessons, "
          f"{with_practice} with Help-me, {with_quiz} with Prove")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
