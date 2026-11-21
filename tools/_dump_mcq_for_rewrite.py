"""Dump Sec+ MCQ choices BEFORE letter rotation (generator order)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT))

import build_secplus_phase1 as build  # noqa: E402
import gen_secplus_d1 as d1  # noqa: E402
import gen_secplus_d2b as d2  # noqa: E402
import gen_secplus_d3 as d3  # noqa: E402
import gen_secplus_d4 as d4  # noqa: E402
import gen_secplus_d5 as d5  # noqa: E402


def main() -> None:
    build.LESSON_SPECS.clear()
    d1.d1_specs(build.add, build._mc, build._qz)
    d2.d2_specs(build.add, build._mc, build._qz)
    d3.d3_specs(build.add, build._mc, build._qz)
    d4.d4_specs(build.add, build._mc, build._qz)
    d5.d5_specs(build.add, build._mc, build._qz)

    rows = []
    for spec in build.LESSON_SPECS:
        lid = spec["id"]
        for pi, p in enumerate(spec["practice"]):
            ch = p.get("choices") or []
            if len(ch) != 4:
                continue
            rows.append(
                {
                    "id": f"{lid}_p{pi + 1}",
                    "bank": "practice",
                    "lesson": lid,
                    "stem": p.get("prompt", ""),
                    "choices": list(ch),
                    "answer_idx": int(p["answer_idx"]),
                }
            )
        for q in spec["quiz"]:
            ch = q.get("choices") or []
            if len(ch) != 4:
                continue
            rows.append(
                {
                    "id": q["id"],
                    "bank": "quiz",
                    "lesson": lid,
                    "stem": q.get("q", ""),
                    "choices": list(ch),
                    "answer_idx": int(q["answer_idx"]),
                }
            )
    out = ROOT / "tools" / "_mcq_export.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"wrote {len(rows)} pre-rotation MCQs -> {out}")


if __name__ == "__main__":
    main()
