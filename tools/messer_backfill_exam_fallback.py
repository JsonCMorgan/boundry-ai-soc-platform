#!/usr/bin/env python3
"""Copy current practice banks into practice_exam_fallback if missing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from tools.messer_notes_quiz_batch import write_curriculum_atomic  # noqa: E402


def main() -> int:
    path = messer_work_dir() / "curriculum" / "701_curriculum.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    fb = dict(data.get("practice_exam_fallback") or {})
    practice = dict(data.get("practice") or {})
    for lid, bank in practice.items():
        if lid not in fb and bank:
            fb[lid] = bank
    data["practice_exam_fallback"] = fb
    write_curriculum_atomic(path, data)
    print(f"Backfilled {len(fb)} lessons -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
