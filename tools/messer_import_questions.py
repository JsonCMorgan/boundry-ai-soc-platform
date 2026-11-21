#!/usr/bin/env python3
"""Parse Messer practice exam PDF text into messer_items (run with Flask app context or sqlite)."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


CHOICE_LINE = re.compile(r"^\s*([A-D])[\.)]\s+(.+)$", re.MULTILINE)
CHOICE_BULLET = re.compile(r"^[❍○]?\s*([A-D])\.\s*(.+)$", re.MULTILINE)
ANSWER_KEY = re.compile(r"(?:Answer|Correct)[:\s]+([A-D])", re.I)
OBJECTIVE_LINE = re.compile(r"(SY0-\d+,\s*Objective\s*[\d.]+)", re.I)


def parse_practice_exam_text(text: str, exam_id: str, provenance: dict) -> list[dict]:
    """Best-effort MCQ parse from extracted PDF plain text."""
    items: list[dict] = []
    chunks = re.split(r"(?=\n\s*\d{1,3}[\.)]\s+)", text)
    qnum = 0
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        m = re.match(r"^(\d{1,3})[\.)]\s+([\s\S]+)", chunk)
        if not m:
            continue
        body = m.group(2)
        choices: list[str] = []
        for cm in CHOICE_LINE.finditer(body):
            choices.append(cm.group(2).strip())
        if len(choices) < 2:
            continue
        stem = re.split(r"\n\s*[A-D][\.)]\s+", body, maxsplit=1)[0].strip()
        ans_m = ANSWER_KEY.search(chunk)
        answer = ans_m.group(1).upper() if ans_m else "A"
        qnum += 1
        item_id = f"messer:pe:{exam_id}:q{qnum:03d}"
        items.append({
            "item_id": item_id,
            "source": f"practice_exam:{exam_id}",
            "stem": stem,
            "choices": choices[:4],
            "answer_key": answer,
            "explain": "",
            "provenance": provenance,
        })
    return items


def _messer_detailed_answer_start(full_text: str, exam_letter: str) -> int:
    """Skip page headers; land on first detailed MCQ block for this exam."""
    pat = re.compile(
        rf"Practice Exam {exam_letter} - Answers[\s\S]{{0,2500}}?"
        rf"{exam_letter}\d+\.\s+[\s\S]{{0,1200}}?❍A\.",
        re.MULTILINE,
    )
    m = pat.search(full_text)
    return m.start() if m else -1


def parse_messer_exam_mcqs(full_text: str, exam_letter: str, exam_id_base: str) -> list[dict]:
    """Parse MCQs from Messer detailed-answer sections (❍ choices + The Answer:)."""
    start = _messer_detailed_answer_start(full_text, exam_letter)
    if start < 0:
        return []
    end = len(full_text)
    for other in ("A", "B", "C"):
        if other == exam_letter:
            continue
        pos = _messer_detailed_answer_start(full_text, other)
        if pos > start:
            end = min(end, pos)
    section = full_text[start:end]
    exam_id = f"{exam_id_base}_exam_{exam_letter.lower()}"
    parts = re.split(rf"(?:^|\n)([{exam_letter}]\d+)\.\s+", section)
    items: list[dict] = []
    for i in range(1, len(parts), 2):
        qtag = parts[i]
        body = parts[i + 1]
        if "❍A." not in body and not CHOICE_BULLET.search(body):
            continue
        ans_m = re.search(r"The Answer:\s*([A-D])\.\s*([^\n]+)", body)
        if not ans_m:
            continue
        answer_key = ans_m.group(1).upper()
        answer_title = re.sub(r"\s+", " ", ans_m.group(2).strip())
        stem_end = body.find("❍")
        stem = (body[:stem_end] if stem_end > 0 else body.split("The Answer:")[0]).strip()
        stem = re.sub(r"\s+", " ", stem)
        choices: list[str] = []
        for cm in CHOICE_BULLET.finditer(body):
            choice = re.sub(r"\s+", " ", cm.group(2).strip())
            if choice and (not choices or choices[-1] != choice):
                choices.append(choice)
        if len(choices) < 2:
            continue
        obj_m = OBJECTIVE_LINE.search(body)
        objective_ref = obj_m.group(1) if obj_m else ""
        explain = ""
        correct_explain = answer_title
        inc = body.find("The incorrect answers:")
        if inc >= 0:
            between = re.sub(r"\s+", " ", body[ans_m.end() : inc].strip())
            if between:
                correct_explain = f"{answer_title} — {between}"
            more = body.find("More information:", inc)
            explain = body[inc : more if more > 0 else len(body)].strip()[:2500]
        more_info = ""
        mo = body.find("More information:")
        if mo >= 0:
            more_info = re.sub(r"\s+", " ", body[mo + len("More information:") :].strip())[:800]
            more_info = re.split(r"\n[A-Z]\d+\.\s", more_info, maxsplit=1)[0].strip()
        qnum = int(re.sub(r"\D", "", qtag) or (len(items) + 1))
        item_id = f"messer:pe:{exam_id}:q{qnum:03d}"
        items.append({
            "item_id": item_id,
            "source": f"practice_exam:{exam_id}",
            "objective_ref": objective_ref,
            "stem": stem,
            "choices": choices[:4],
            "answer_key": answer_key,
            "explain": explain,
            "provenance": {
                "exam_letter": exam_letter,
                "qtag": qtag,
                "correct_explain": correct_explain[:2000],
                "more_info": more_info[:800],
            },
        })
    return items


def parse_messer_practice_pdf(full_text: str, exam_id_base: str, provenance: dict) -> list[dict]:
    """Exam A/B/C from one Messer practice-exams PDF."""
    items: list[dict] = []
    for letter in ("A", "B", "C"):
        items.extend(parse_messer_exam_mcqs(full_text, letter, exam_id_base))
    if items:
        return items
    return parse_practice_exam_text(full_text, exam_id_base, provenance)


def load_extracted_practice_pdf(work_dir: Path) -> tuple[str, str] | None:
    extracted = work_dir / "extracted"
    if not extracted.is_dir():
        return None
    candidates = [
        p for p in sorted(extracted.glob("*.json"))
        if "practice" in p.name.lower() and "exam" in p.name.lower()
    ]
    if not candidates:
        candidates = [p for p in sorted(extracted.glob("*.json")) if "practice" in p.name.lower()]
    for p in candidates:
        data = json.loads(p.read_text(encoding="utf-8"))
        text = "\n".join(page.get("text") or "" for page in data.get("pages") or [])
        exam_id = re.sub(r"[^a-z0-9]+", "_", p.stem.lower())[:48]
        return exam_id, text
    return None


def import_to_db(items: list[dict]) -> int:
    import app as app_module
    import messer_layer

    messer_layer.configure(
        app_module.db_fetchone,
        app_module.db_fetchall,
        app_module.db_run,
        app_module.PH,
    )
    for it in items:
        messer_layer.upsert_item(it)
    return len(items)


def main() -> int:
    from messer_paths import messer_work_dir

    work = messer_work_dir()
    pair = load_extracted_practice_pdf(work)
    if not pair:
        print("No extracted practice exam JSON found. Run messer_extract.py after inventory.")
        return 1
    exam_id, text = pair
    items = parse_messer_practice_pdf(text, exam_id, provenance={"exam_id": exam_id})
    review_path = work / "imports" / "messer_import_review.json"
    review_path.parent.mkdir(parents=True, exist_ok=True)
    low_conf = [it for it in items if len(it.get("choices") or []) < 4]
    review_path.write_text(json.dumps({
        "exam_id": exam_id,
        "parsed": len(items),
        "low_confidence_count": len(low_conf),
        "sample_ids": [it["item_id"] for it in items[:5]],
    }, indent=2), encoding="utf-8")
    if not items:
        print("Parse yielded 0 items; check PDF extract quality")
        return 1
    n = import_to_db(items)
    print(f"Imported {n} items for exam {exam_id}")
    print(f"Review: {review_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
