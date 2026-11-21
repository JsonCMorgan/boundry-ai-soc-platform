#!/usr/bin/env python3
"""Generate note-grounded Help-me (3) and Prove-it (5 min) for Messer sessions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from notes_quiz_generator import generate_notes_help, generate_notes_prove  # noqa: E402
from tools.messer_notes_quiz_batch import (  # noqa: E402
    PROVE_MIN,
    append_batch_log,
    apply_lesson_help_to_payload,
    apply_lesson_prove_to_payload,
    failed_lesson_ids_from_log,
    has_notes_help,
    has_notes_prove,
    notes_eligible,
    study_source_body,
    write_curriculum_atomic,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate notes-based Help and Prove for Messer lessons")
    parser.add_argument("--lesson", type=str, default="", help="Single lesson id e.g. ms_0101_01")
    parser.add_argument("--force", action="store_true", help="Ignore cache and regenerate")
    parser.add_argument("--limit", type=int, default=0, help="Max successful lesson updates (0=all)")
    parser.add_argument(
        "--prove-only",
        action="store_true",
        help="Regenerate Prove-it only (5+ from notes)",
    )
    parser.add_argument(
        "--help-only",
        action="store_true",
        help="Regenerate Help-me only",
    )
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Only lessons whose last batch log status was fail",
    )
    args = parser.parse_args()

    work = messer_work_dir()
    path = work / "curriculum" / "701_curriculum.json"
    if not path.is_file():
        print("Run tools/messer_build_curriculum.py first")
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    lessons = data.get("lessons") or []

    if args.lesson:
        lessons = [L for L in lessons if L["id"] == args.lesson]
        if not lessons:
            print(f"Unknown lesson {args.lesson}")
            return 1

    if args.retry_failed:
        retry_set = set(failed_lesson_ids_from_log(work))
        if not retry_set:
            print("No failed lessons in batch log")
            return 0
        lessons = [L for L in lessons if L["id"] in retry_set]

    n_ok = 0
    n_fail = 0
    n_skip = 0
    do_help = not args.prove_only
    do_prove = not args.help_only

    for L in lessons:
        if args.limit and n_ok >= args.limit:
            break
        lid = L["id"]
        eligible, reason = notes_eligible(L)
        if not eligible:
            print(f"SKIP {lid} ({reason} notes)")
            append_batch_log(work, lesson_id=lid, status=f"skip_{reason}")
            n_skip += 1
            continue

        notes = study_source_body(L)
        existing_help = list((data.get("practice") or {}).get(lid) or [])
        existing_quiz = list((data.get("quizzes") or {}).get(lid) or [])

        if do_help and not args.force and has_notes_help(existing_help):
            help_skip = True
        else:
            help_skip = False

        if do_prove and not args.force and has_notes_prove(existing_quiz):
            prove_skip = True
        else:
            prove_skip = False

        if (do_help and help_skip) and (do_prove and prove_skip):
            print(f"SKIP {lid} (help and prove already complete)")
            append_batch_log(
                work,
                lesson_id=lid,
                status="skip_done",
                help_count=len(existing_help),
                prove_count=len(existing_quiz),
            )
            n_skip += 1
            continue

        try:
            if args.force:
                from notes_quiz_generator import cache_path

                cp = cache_path(work, lid)
                if cp.is_file():
                    cp.unlink()

            help_count = len(existing_help)
            prove_count = len(existing_quiz)

            if do_help and not help_skip:
                help_items = generate_notes_help(
                    lesson_id=lid,
                    title=L.get("title") or lid,
                    objective_ref=L.get("objective_ref") or "",
                    notes=notes,
                    use_cache=not args.force,
                )
                apply_lesson_help_to_payload(data, L, help_items)
                help_count = len(help_items)
                append_batch_log(work, lesson_id=lid, status="ok_help", help_count=help_count)

            help_prompts = {
                (p.get("prompt") or "")
                for p in (data.get("practice") or {}).get(lid) or []
            }

            if do_prove and not prove_skip:
                prove_items = generate_notes_prove(
                    lesson_id=lid,
                    title=L.get("title") or lid,
                    objective_ref=L.get("objective_ref") or "",
                    notes=notes,
                    help_prompts=help_prompts,
                    use_cache=not args.force,
                )
                if len(prove_items) < PROVE_MIN:
                    raise ValueError(f"Prove bank has {len(prove_items)}; need {PROVE_MIN}")
                prove_count = apply_lesson_prove_to_payload(data, L, prove_items)
                append_batch_log(
                    work,
                    lesson_id=lid,
                    status="ok_prove",
                    prove_count=prove_count,
                )

            write_curriculum_atomic(path, data)
            n_ok += 1
            print(f"OK {lid} - help {help_count}, prove {prove_count}")
        except Exception as exc:
            n_fail += 1
            print(f"FAIL {lid}: {exc}")
            append_batch_log(work, lesson_id=lid, status="fail", error=str(exc))

    print(f"Done - ok={n_ok} fail={n_fail} skip={n_skip} -> {path}")
    if n_fail:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
