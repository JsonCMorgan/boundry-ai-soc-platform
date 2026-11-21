#!/usr/bin/env python3
"""Print progress of the notes MCQ answer audit."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from tools.messer_verify_quiz_answers import EXPECTED_MCQ_TOTAL, REPORT_NAME  # noqa: E402


def main() -> int:
    path = messer_work_dir() / "curriculum" / REPORT_NAME
    if not path.is_file():
        print("No audit report yet. Run: powershell -File tools/messer_run_quiz_audit.ps1")
        return 1
    r = json.loads(path.read_text(encoding="utf-8"))
    n = len(r.get("verified_keys") or [])
    fail = int(r.get("failure_count") or 0)
    complete = bool(r.get("complete"))
    pct = min(100, round(100 * n / EXPECTED_MCQ_TOTAL))
    print(f"Verified: {n}/{EXPECTED_MCQ_TOTAL} ({pct}%)")
    print(f"Failures flagged: {fail}")
    print(f"Complete: {complete}")
    if not complete:
        print("Run: powershell -ExecutionPolicy Bypass -File tools/messer_run_quiz_audit.ps1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
