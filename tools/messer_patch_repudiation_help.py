#!/usr/bin/env python3
"""Fix inverted non-repudiation Help-me MCQs in private curriculum + cache."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_work_dir  # noqa: E402
from notes_quiz_guards import validate_notes_mcq  # noqa: E402
from tools.messer_notes_quiz_batch import write_curriculum_atomic  # noqa: E402

FIXED = {
    "prompt": "What is non-repudiation?",
    "choices": [
        "The ability to deny what you said or did after the fact",
        "Proof that someone cannot credibly deny they sent or signed something",
        "Encrypting data so only authorized users can read it",
        "Keeping systems and services available when hardware fails",
    ],
    "answer_idx": 1,
    "explain": (
        "Correct. Non-repudiation means others can prove you sent or signed something, "
        "and you cannot take it back. The notes use signing a contract as the example. "
        "Common trap: reading non in the name and picking ability to deny. "
        "Remember: you cannot deny what you said."
    ),
    "hint": "Think about signing a contract. The notes say you cannot deny what you said.",
}


def _needs_fix(row: dict) -> bool:
    try:
        validate_notes_mcq({
            "prompt": row.get("prompt") or row.get("q") or "",
            "choices": row.get("choices") or [],
            "answer_idx": int(row.get("answer_idx", 0)),
            "explain": row.get("explain") or row.get("correct_explain") or "",
        })
        return False
    except ValueError:
        return True


def main() -> int:
    work = messer_work_dir()
    path = work / "curriculum" / "701_curriculum.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    n = 0
    for lid, bank in (data.get("practice") or {}).items():
        for i, row in enumerate(bank):
            if not _needs_fix(row):
                continue
            if "non-repudiation" not in (row.get("prompt") or "").lower():
                print(f"SKIP manual review {lid} {row.get('id')}")
                continue
            bank[i] = {
                **row,
                **FIXED,
                "correct_explain": FIXED["explain"],
            }
            n += 1
            print(f"Fixed {lid} {row.get('id')}")

    if n:
        write_curriculum_atomic(path, data)

    cache_dir = work / "curriculum" / "notes_quizzes"
    for cp in cache_dir.glob("*.json"):
        payload = json.loads(cp.read_text(encoding="utf-8"))
        changed = False
        for i, row in enumerate(payload.get("practice") or []):
            if _needs_fix(row) and "non-repudiation" in (row.get("prompt") or "").lower():
                payload["practice"][i] = {**row, **FIXED, "correct_explain": FIXED["explain"]}
                changed = True
        if changed:
            cp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"Updated cache {cp.name}")
    print(f"Done ({n} curriculum fixes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
