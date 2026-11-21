#!/usr/bin/env python3
"""Optional Ollama pass: rewrite Messer notes into professor-style lessons (local, private)."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_lesson_format import (  # noqa: E402
    build_structured_lesson,
    formatted_sidecar_path,
)
from messer_paths import messer_work_dir  # noqa: E402


def _parse_ollama_json(text: str) -> dict | None:
    text = (text or "").strip()
    if not text:
        return None
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


def ollama_format_lesson(
    *,
    title: str,
    objective_ref: str,
    domain_id: str,
    notes_body: str,
    key_terms: list[str],
    messer_session: str,
) -> dict | None:
    import app as app_module

    terms_line = ", ".join(key_terms[:8]) if key_terms else "(extract from notes)"
    prompt = f"""You are a college professor teaching CompTIA Security+ (exam version SY0-701).
Rewrite SOURCE NOTES into a conversational Show-me lesson for one video session.
Rules:
- Define every acronym before you use it.
- No em dashes or en dashes.
- Do not say you copied notes; teach as if live lecture.
- Do not mention Professor Messer or file names.
- Use plain English; exam version SY0-701 must be explained once if referenced.

Return ONLY valid JSON with this shape:
{{
  "sections": [{{"heading": "string", "body": "string"}}],
  "teach_back": {{
    "listener_prompt": "string",
    "explain_aloud": "string",
    "define_first": [{{"term": "string", "say": "string"}}],
    "desk_one_liner": "string",
    "exam_trap": "string",
    "remember": "string"
  }},
  "goal": "one line student outcome"
}}

Include 6-10 sections following: orient, define terms, work picture, technical beats, worked example scenario, how to answer, common trap, remember.

Title: {title}
Objective: {objective_ref}
Session: {messer_session}
Key terms hint: {terms_line}

SOURCE NOTES:
{notes_body[:5200]}
"""
    try:
        raw = app_module._call_ollama(prompt, max_tokens=2200, temperature=0.35)
    except Exception as exc:
        print(f"  Ollama failed: {exc}")
        return None
    data = _parse_ollama_json(raw)
    if not data or not data.get("sections"):
        return None
    data["format"] = "ollama"
    data["source"] = "ollama"
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Format Messer sessions as professor lessons")
    parser.add_argument("--limit", type=int, default=0, help="Max sessions to process (0 = all)")
    parser.add_argument("--force", action="store_true", help="Overwrite existing sidecars")
    parser.add_argument("--structured-only", action="store_true", help="Skip Ollama; structural rewrite only")
    parser.add_argument("--lesson", type=str, default="", help="Single lesson id e.g. ms_0101_01")
    args = parser.parse_args()

    curriculum_path = messer_work_dir() / "curriculum" / "701_curriculum.json"
    if not curriculum_path.is_file():
        print("Run tools/messer_build_curriculum.py first")
        return 1
    curriculum = json.loads(curriculum_path.read_text(encoding="utf-8"))
    lessons = curriculum.get("lessons") or []
    if args.lesson:
        lessons = [L for L in lessons if L.get("id") == args.lesson]
        if not lessons:
            print(f"Unknown lesson {args.lesson}")
            return 1

    out_dir = messer_work_dir() / "curriculum" / "formatted"
    out_dir.mkdir(parents=True, exist_ok=True)

    n = 0
    for L in lessons:
        lid = L["id"]
        side_path = formatted_sidecar_path(lid)
        if side_path.is_file() and not args.force:
            continue
        notes_body = (L.get("notes_raw") or "").strip()
        if not notes_body:
            for sec in L.get("sections") or []:
                if sec.get("heading") == "Course notes":
                    notes_body = sec.get("body") or ""
        if not notes_body:
            for sec in L.get("sections") or []:
                if sec.get("heading") not in (
                    "Orient",
                    "What we are doing today",
                    "Where you will use this",
                    "How to answer on exam day",
                    "Common trap",
                    "Remember",
                ):
                    notes_body += (sec.get("body") or "") + "\n"
        title = L.get("title") or lid
        formatted = None
        if not args.structured_only:
            formatted = ollama_format_lesson(
                title=title,
                objective_ref=L.get("objective_ref") or "",
                domain_id=L.get("domain_id") or "d1_concepts",
                notes_body=notes_body,
                key_terms=L.get("key_terms") or [],
                messer_session=L.get("messer_session") or "",
            )
        if not formatted:
            formatted = build_structured_lesson(
                title=title,
                objective_ref=L.get("objective_ref") or "",
                domain_id=L.get("domain_id") or "d1_concepts",
                notes_body=notes_body,
                key_terms=L.get("key_terms") or [],
                messer_session=L.get("messer_session") or "",
            )
        side_path.write_text(json.dumps(formatted, indent=2, ensure_ascii=False), encoding="utf-8")
        n += 1
        print(f"Wrote {side_path.name} ({formatted.get('format', '?')})")
        if args.limit and n >= args.limit:
            break

    print(f"Formatted {n} lesson(s). Re-run: python tools/messer_build_curriculum.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
