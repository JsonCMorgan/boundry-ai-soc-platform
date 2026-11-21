"""Report Sec+ Help-me / Prove-it choices that look truncated or incomplete."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from secplus_lessons import PRACTICE, QUIZZES  # noqa: E402
from secplus_mcq_length_lint import (  # noqa: E402
    incomplete_choice_reasons,
    lint_mcq_incomplete,
)


def main() -> int:
    """Print every incomplete choice, then summary. Exit 1 if any found."""
    rows: list[str] = []
    banks = (("practice", PRACTICE, "prompt"), ("quiz", QUIZZES, "q"))
    for bank_name, bank, stem_key in banks:
        for lesson_id, items in bank.items():
            for item in items:
                choices = item.get("choices") or []
                if len(choices) != 4:
                    continue
                qid = item.get("id", lesson_id)
                stem = (
                    item.get(stem_key)
                    or item.get("prompt")
                    or item.get("q")
                    or ""
                )[:80]
                for i, choice in enumerate(choices):
                    reasons = incomplete_choice_reasons(choice)
                    if not reasons:
                        continue
                    rows.append(
                        f"{bank_name}:{qid} [{i}] {','.join(reasons)} "
                        f":: {choice}\n  stem: {stem}"
                    )
    for line in rows:
        print(line)
        print()
    offenders = lint_mcq_incomplete(PRACTICE, QUIZZES, hard_fail=False)
    if offenders:
        print(f"FAIL: {len(offenders)} incomplete choice(s).")
        return 1
    print("OK: no incomplete choices.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
