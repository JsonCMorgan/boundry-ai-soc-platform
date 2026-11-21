#!/usr/bin/env python3
"""Verify every notes Help / Prove MCQ against session course notes (guards + Ollama)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from notes_quiz_guards import validate_notes_mcq  # noqa: E402
from notes_quiz_verify import verify_mcq_detail  # noqa: E402
from tools.messer_notes_quiz_batch import (  # noqa: E402
    has_notes_help,
    notes_eligible,
    study_source_body,
    write_curriculum_atomic,
)


REPORT_NAME = "quiz_answer_verify_report.json"
LOCK_NAME = ".quiz_verify.lock"
EXPECTED_MCQ_TOTAL = 910


def _lock_path() -> Path:
    return messer_work_dir() / "curriculum" / LOCK_NAME


def _acquire_verify_lock() -> None:
    lp = _lock_path()
    if lp.is_file():
        try:
            old = int(lp.read_text(encoding="utf-8").strip())
            os.kill(old, 0)
        except (OSError, ValueError, ProcessLookupError):
            lp.unlink(missing_ok=True)
        else:
            raise SystemExit(
                f"Another verify run is active (pid {old}). "
                "Wait for it, or stop that process and delete .quiz_verify.lock"
            )
    lp.write_text(str(os.getpid()), encoding="utf-8")


def _release_verify_lock() -> None:
    _lock_path().unlink(missing_ok=True)


def _item_key(lesson_id: str, bank: str, item: dict[str, Any]) -> str:
    iid = item.get("id") or item.get("item_id") or ""
    stem = (item.get("q") or item.get("prompt") or "")[:120]
    return f"{lesson_id}|{bank}|{iid}|{stem}"


def _mcq_row(
    *,
    lesson_id: str,
    bank: str,
    item: dict[str, Any],
) -> dict[str, Any]:
    return {
        "lesson_id": lesson_id,
        "bank": bank,
        "id": item.get("id") or item.get("item_id") or "",
        "item_key": _item_key(lesson_id, bank, item),
        "q": (item.get("q") or item.get("prompt") or "")[:240],
        "answer_idx": int(item.get("answer_idx", 0)),
        "choices": item.get("choices") or [],
    }


def _check_one(notes: str, item: dict[str, Any]) -> dict[str, Any]:
    mcq = {
        "prompt": item.get("q") or item.get("prompt"),
        "choices": item.get("choices"),
        "answer_idx": item.get("answer_idx"),
        "explain": item.get("explain") or item.get("correct_explain"),
    }
    try:
        validate_notes_mcq(mcq, notes=notes)
        guard_ok = True
        guard_err = ""
    except ValueError as exc:
        guard_ok = False
        guard_err = str(exc)
    detail = verify_mcq_detail(notes, mcq)
    return {
        "guard_ok": guard_ok,
        "guard_error": guard_err,
        "ollama_pass": detail.get("pass"),
        "ollama_reason": detail.get("reason") or "",
        "better_index": detail.get("better_index"),
    }


def _apply_fixes(data: dict[str, Any], failures: list[dict[str, Any]]) -> int:
    """Apply better_index from Ollama when guard failed or ollama failed with a suggestion."""
    practice = data.setdefault("practice", {})
    quizzes = data.setdefault("quizzes", {})
    cache_dir = messer_work_dir() / "curriculum" / "notes_quizzes"
    touched_lessons: set[str] = set()
    n = 0

    for f in failures:
        bi = f.get("better_index")
        if bi is None:
            continue
        if f.get("guard_ok") is not False and f.get("ollama_pass") is not False:
            continue
        lid = f["lesson_id"]
        bank_name = f.get("bank")
        bank = practice.get(lid) if bank_name == "help" else quizzes.get(lid)
        if not bank:
            continue
        target_id = f.get("id") or ""
        for item in bank:
            iid = item.get("id") or item.get("item_id") or ""
            if target_id and iid != target_id:
                continue
            if int(item.get("answer_idx", -1)) == int(bi):
                break
            item["answer_idx"] = int(bi)
            n += 1
            f["applied"] = True
            touched_lessons.add(lid)
            break

    for lid in touched_lessons:
        cp = cache_dir / f"{lid}.json"
        if not cp.is_file():
            continue
        cached = json.loads(cp.read_text(encoding="utf-8"))
        if practice.get(lid):
            cached["practice"] = practice[lid]
        if quizzes.get(lid):
            cached["quizzes"] = quizzes[lid]
        cp.write_text(json.dumps(cached, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return n


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify all notes MCQ answer keys")
    parser.add_argument("--lesson", help="Single lesson id, e.g. ms_0102_06")
    parser.add_argument("--prove-only", action="store_true")
    parser.add_argument("--help-only", action="store_true")
    parser.add_argument("--skip-ollama", action="store_true", help="Deterministic guards only")
    parser.add_argument("--apply", action="store_true", help="Apply Ollama better_index fixes to curriculum")
    parser.add_argument("--limit", type=int, default=0, help="Max MCQs to verify (0 = all)")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip item_keys already in quiz_answer_verify_report.json",
    )
    args = parser.parse_args()

    if args.apply:
        path = messer_work_dir() / "curriculum" / REPORT_NAME
        if not path.is_file():
            print("No report — run verify first")
            return 1
        report = json.loads(path.read_text(encoding="utf-8"))
        failures = list(report.get("failures") or [])
        cur_path = messer_work_dir() / "curriculum" / "701_curriculum.json"
        data = json.loads(cur_path.read_text(encoding="utf-8"))
        applied = _apply_fixes(data, failures)
        if applied:
            write_curriculum_atomic(cur_path, data)
            print(f"Applied {applied} answer_idx fix(es)")
        else:
            print("No fixes applied")
        return 0

    _acquire_verify_lock()
    try:
        return _run_verify(args)
    finally:
        _release_verify_lock()


def _run_verify(args: argparse.Namespace) -> int:
    if args.skip_ollama:
        import os

        os.environ["MESSER_QUIZ_SKIP_VERIFY"] = "1"

    path = messer_work_dir() / "curriculum" / "701_curriculum.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    lessons = data.get("lessons") or []
    if args.lesson:
        lessons = [L for L in lessons if L["id"] == args.lesson]
        if not lessons:
            print(f"Unknown lesson {args.lesson}")
            return 1

    do_help = not args.prove_only
    do_prove = not args.help_only
    checked = 0
    skipped = 0
    failures: list[dict[str, Any]] = []
    done_keys: set[str] = set()
    report_path = messer_work_dir() / "curriculum" / REPORT_NAME
    if args.resume and report_path.is_file():
        prev = json.loads(report_path.read_text(encoding="utf-8"))
        failures = list(prev.get("failures") or [])
        done_keys = set(prev.get("verified_keys") or [])
        if prev.get("complete"):
            print(f"Report already complete ({len(done_keys)} items). Delete report or omit --resume.")
            return 0

    def _write_report(*, complete: bool = False) -> None:
        report_path.write_text(
            json.dumps(
                {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "checked": checked,
                    "skipped_resume": skipped,
                    "verified_keys": sorted(done_keys),
                    "failures": failures,
                    "failure_count": len(failures),
                    "complete": complete,
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )

    for L in lessons:
        lid = L["id"]
        eligible, reason = notes_eligible(L)
        if not eligible:
            continue
        notes = study_source_body(L)
        if len(notes) < 50:
            continue

        batches: list[tuple[str, list[dict[str, Any]]]] = []
        if do_help:
            help_bank = list((data.get("practice") or {}).get(lid) or [])
            if has_notes_help(help_bank):
                batches.append(("help", help_bank))
        if do_prove:
            prove_bank = list((data.get("quizzes") or {}).get(lid) or [])
            batches.append(("prove", prove_bank))

        for bank_name, bank in batches:
            for item in bank:
                if args.limit and checked >= args.limit:
                    break
                if bank_name == "prove" and ":notes:prove:" not in (item.get("id") or ""):
                    continue
                if bank_name == "help":
                    iid = item.get("id") or item.get("item_id") or ""
                    if iid.startswith("messer:"):
                        continue
                row = _mcq_row(lesson_id=lid, bank=bank_name, item=item)
                key = row["item_key"]
                if key in done_keys:
                    skipped += 1
                    continue
                result = _check_one(notes, item)
                done_keys.add(key)
                checked += 1
                if checked == 1 or checked % 25 == 0:
                    print(f"... checked {checked} (skipped {skipped})", flush=True)
                _write_report()
                ok = result["guard_ok"] and result["ollama_pass"]
                if not ok:
                    fail = {**row, **result}
                    failures.append(fail)
                    tag = "GUARD" if not result["guard_ok"] else "OLLAMA"
                    print(f"FAIL [{tag}] {lid} {bank_name} idx={row['answer_idx']} {row['q'][:70]}")
                    if result["guard_error"]:
                        print(f"       guard: {result['guard_error']}")
                    if not result["ollama_pass"]:
                        print(f"       ollama: {result['ollama_reason']}")
                    if result.get("better_index") is not None:
                        print(f"       suggest idx: {result['better_index']}")
            if args.limit and checked >= args.limit:
                break
        if args.limit and checked >= args.limit:
            break

    _write_report(complete=True)

    print(f"\nChecked {checked} MCQs (skipped {skipped} resume) — failures: {len(failures)}")
    print(f"Report: {report_path}")

    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
