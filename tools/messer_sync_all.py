#!/usr/bin/env python3
"""Run full Messer ingest pipeline (inventory → extract → map → import)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STEPS = [
    [sys.executable, str(ROOT / "tools" / "messer_inventory.py")],
    [sys.executable, str(ROOT / "tools" / "messer_extract.py")],
    [sys.executable, str(ROOT / "tools" / "messer_build_session_map.py")],
    [sys.executable, str(ROOT / "tools" / "messer_import_questions.py")],
    [sys.executable, str(ROOT / "tools" / "messer_build_curriculum.py")],
    [sys.executable, str(ROOT / "tools" / "messer_coverage_report.py")],
]


def main() -> int:
    for cmd in STEPS:
        print(">>", " ".join(cmd))
        rc = subprocess.call(cmd, cwd=str(ROOT))
        if rc != 0:
            print(f"Step failed with code {rc}: {cmd[-1]}")
            return rc
    print("Messer sync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
