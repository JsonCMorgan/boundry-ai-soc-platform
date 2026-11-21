#!/usr/bin/env python3
"""Audit Messer curriculum Help/Prove sourcing (notes vs exam)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from tools.messer_notes_quiz_batch import (  # noqa: E402
    PROVE_MIN,
    batch_log_path,
    failed_lesson_ids_from_log,
    has_notes_help,
    has_notes_prove,
    notes_eligible,
    study_source_body,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit Messer notes Help/Prove banks")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero on any gap or invalid prove id")
    args = parser.parse_args()

    path = messer_work_dir() / "curriculum" / "701_curriculum.json"
    if not path.is_file():
        print("Missing 701_curriculum.json — run messer_build_curriculum.py")
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    lessons = data.get("lessons") or []
    practice = data.get("practice") or {}
    quizzes = data.get("quizzes") or {}

    ok_notes = thin = missing = 0
    notes_help = exam_help = no_help = 0
    prove_ok = prove_gap = 0
    bad_prove_ids = 0

    for L in lessons:
        lid = L["id"]
        eligible, reason = notes_eligible(L)
        if reason == "ok":
            ok_notes += 1
        elif reason == "thin":
            thin += 1
        else:
            missing += 1

        bank = practice.get(lid) or []
        if not bank:
            no_help += 1
        elif has_notes_help(bank):
            notes_help += 1
        else:
            exam_help += 1

        qbank = quizzes.get(lid) or []
        if eligible and has_notes_prove(qbank):
            prove_ok += 1
        elif eligible:
            prove_gap += 1
        for q in qbank:
            if ":notes:prove:" not in (q.get("id") or ""):
                bad_prove_ids += 1

    failed = failed_lesson_ids_from_log(messer_work_dir())
    log_path = batch_log_path(messer_work_dir())

    print(f"Lessons: {len(lessons)}")
    print(f"Study source eligible: ok={ok_notes} thin={thin} missing={missing}")
    print(f"Help-me: notes={notes_help} exam_only={exam_help} empty={no_help}")
    print(f"Prove-it (>={PROVE_MIN} notes): ok={prove_ok} gap={prove_gap}")
    print(f"quiz_source: {data.get('quiz_source') or '(unset)'}")
    if bad_prove_ids:
        print(f"Non-notes Prove ids in quizzes: {bad_prove_ids}")
    if log_path.is_file():
        print(f"Batch log: {log_path} (failed ids: {len(failed)})")
        if failed:
            print("  " + ", ".join(failed[:20]) + ("..." if len(failed) > 20 else ""))

    if args.strict:
        from notes_quiz_guards import validate_prove_bank

        for L in lessons:
            lid = L["id"]
            if not notes_eligible(L)[0]:
                continue
            qbank = quizzes.get(lid) or []
            notes = study_source_body(L)
            hp = {(p.get("prompt") or "") for p in (practice.get(lid) or [])}
            try:
                validate_prove_bank(qbank, notes=notes, help_prompts=hp, min_count=PROVE_MIN)
            except ValueError as exc:
                print(f"STRICT FAIL {lid}: {exc}")
                return 2
            for q in qbank:
                if ":notes:prove:" not in (q.get("id") or ""):
                    print(f"STRICT FAIL {lid}: non-notes prove id {q.get('id')}")
                    return 2
        if notes_help < ok_notes or prove_gap:
            print(f"STRICT FAIL gaps help={ok_notes - notes_help} prove={prove_gap}")
            return 2

    eligible_n = ok_notes
    if notes_help < eligible_n:
        print(f"Gap: {eligible_n - notes_help} eligible lessons still lack notes Help")
        return 2 if args.strict else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
