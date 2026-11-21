"""Ensure every Show-me section has a Watch out beat; refresh weak Analogy lines."""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ROOT / "tools" / "gen_secplus_d2b.py",
    ROOT / "tools" / "gen_secplus_d3.py",
    ROOT / "tools" / "gen_secplus_d4.py",
    ROOT / "tools" / "gen_secplus_d5.py",
]

WEAK_ANALOGY = "Analogy: start with one everyday picture, then lock the exam term."
BETTER_ANALOGY = (
    "Analogy: pause like a good YouTube tutor. One everyday picture first, "
    "then the CompTIA term so it sticks."
)


def transform(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    n = 0
    text2 = text.replace(WEAK_ANALOGY, BETTER_ANALOGY)
    if text2 != text:
        n += text.count(WEAK_ANALOGY)
        text = text2

    parts: list[str] = []
    last = 0
    for m in re.finditer(r'"""(.*?)"""', text, re.S):
        parts.append(text[last : m.start()])
        inner = m.group(1)
        if "Hook:" in inner and "Watch out" not in inner and len(inner) > 100:
            # Insert Watch out before Remember, or append
            if re.search(r"(?im)Remember:", inner):
                inner2, c = re.subn(
                    r"(?im)(Remember:)",
                    "Watch out: the distractor usually mixes this idea with a nearby "
                    "lookalike term or skips the step the stem is testing.\n\n\\1",
                    inner,
                    count=1,
                )
                if c:
                    n += 1
                    inner = inner2
            else:
                inner = (
                    inner.rstrip()
                    + "\n\nWatch out: the distractor usually mixes this idea with a "
                    "nearby lookalike term.\n\nRemember: pick the class the stem "
                    "actually shows."
                )
                n += 1
        parts.append('"""' + inner + '"""')
        last = m.end()
    parts.append(text[last:])
    out = "".join(parts)
    ast.parse(out)
    path.write_text(out, encoding="utf-8")
    return n


def main() -> None:
    for p in TARGETS:
        print(p.name, transform(p))


if __name__ == "__main__":
    main()
