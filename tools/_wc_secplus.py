"""Word-count summary for Security+ lessons by domain."""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secplus_lessons import LESSONS  # noqa: E402


def word_count(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def lesson_body(lesson: dict) -> str:
    parts: list[str] = []
    for sec in lesson.get("sections") or []:
        if isinstance(sec, dict):
            parts.append(str(sec.get("heading") or ""))
            parts.append(str(sec.get("body") or ""))
        elif isinstance(sec, (list, tuple)) and len(sec) >= 2:
            parts.append(str(sec[0]))
            parts.append(str(sec[1]))
    return "\n".join(parts)


def main() -> None:
    by: dict[int, list[tuple[str, int, str, int]]] = defaultdict(list)
    for lesson in LESSONS:
        lid = lesson["id"]
        dom = int(lesson.get("domain_order") or 0)
        body = lesson_body(lesson)
        title = (lesson.get("title") or "")[:55]
        tech_len = word_count(
            "\n".join(
                m.group(1)
                for m in re.finditer(
                    r"Technical specifics[^\n]*\n(.*?)(?:\n\nWorked example:|\n\nHow to answer)",
                    body,
                    flags=re.S | re.I,
                )
            )
        )
        by[dom].append((lid, word_count(body), title, tech_len))

    for dom in sorted(by):
        items = by[dom]
        ws = [w for _, w, _, _ in items]
        avg = sum(ws) / len(ws)
        thin = sum(1 for w in ws if w < 400)
        print(
            f"=== Domain {dom}: n={len(items)} avg={avg:.0f} "
            f"min={min(ws)} max={max(ws)} under400={thin} ==="
        )
        for lid, w, title, tech in sorted(items, key=lambda x: x[1]):
            flag = " THIN" if w < 400 else ""
            print(f"  {w:4d}  tech~{tech:3d}  {lid}{flag}  {title}")


if __name__ == "__main__":
    main()
