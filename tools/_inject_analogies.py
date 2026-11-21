"""Inject Analogy bridges and lowercase boilerplate Hook topics in D2–D5."""
from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {"gen_secplus_d1.py", "gen_secplus_phase1.py", "gen_secplus_d2.py"}


def main() -> None:
    for p in sorted((ROOT / "tools").glob("gen_secplus_d*.py")):
        if p.name in SKIP:
            continue
        t = p.read_text(encoding="utf-8")

        def low(m: re.Match[str]) -> str:
            topic = m.group(1)
            if topic and topic[0].isupper():
                topic = topic[0].lower() + topic[1:]
            return "stem about " + topic

        t = re.sub(r"stem about ([^\.]+)", low, t)

        parts: list[str] = []
        last = 0
        for m in re.finditer(r'"""(.*?)"""', t, re.S):
            parts.append(t[last : m.start()])
            inner = m.group(1)
            if "Hook:" in inner and "Analogy:" not in inner and len(inner) > 120:
                inner = re.sub(
                    r"(Hook:[^\n]+\n\n)",
                    r"\1Analogy: start with one everyday picture, then lock the exam term.\n\n",
                    inner,
                    count=1,
                )
            parts.append('"""' + inner + '"""')
            last = m.end()
        parts.append(t[last:])
        out = "".join(parts)
        out = re.sub(
            r"Voice:.*",
            "Voice: YouTube-tutor methods for SY0-701 (see VOICE GUIDE in build_secplus_phase1.py).",
            out,
            count=1,
        )
        ast.parse(out)
        p.write_text(out, encoding="utf-8")
        print(p.name, "Analogy", out.count("Analogy:"), "Hook", out.count("Hook:"))


if __name__ == "__main__":
    main()
