#!/usr/bin/env python3
"""Report SY0-801 objectives vs Boundry lessons vs Messer session map."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import secplus_learn  # noqa: E402
from messer_catalog import load_session_map  # noqa: E402


def main() -> int:
    objectives_path = ROOT / "docs" / "exam-outlines" / "sy0-801-objectives.json"
    objs = []
    if objectives_path.is_file():
        data = json.loads(objectives_path.read_text(encoding="utf-8"))
        objs = [o.get("id") or o.get("objective_ref") for o in data.get("objectives") or []]
    sessions = load_session_map()
    sess_by_obj: dict[str, int] = {}
    for s in sessions:
        ref = s.get("objective_ref") or ""
        sess_by_obj[ref] = sess_by_obj.get(ref, 0) + 1
    lesson_objs = {L.get("objective_ref") for L in secplus_learn.LESSONS}
    lines = ["# Messer ↔ Boundry coverage (generated)", ""]
    for ref in sorted(set(objs) | lesson_objs):
        lines.append(
            f"- {ref}: lessons={sum(1 for L in secplus_learn.LESSONS if L.get('objective_ref')==ref)} "
            f"messer_sessions={sess_by_obj.get(ref, 0)}"
        )
    out = ROOT / "content" / "private" / "messer" / "coverage_report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
