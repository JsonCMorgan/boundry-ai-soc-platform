"""Fix leftover boilerplate Hooks and doubled Watch-out phrases in D2–D5 gens."""
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

BOILER_HOOK = re.compile(
    r"Hook:\s*master this for SY0-701 under time pressure\.\s*"
    r"Topic:\s*([^\n.]+)\.",
    re.IGNORECASE,
)


def fix(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    n = 0

    def hook_repl(m: re.Match[str]) -> str:
        nonlocal n
        n += 1
        topic = m.group(1).strip()
        return (
            f"Hook: picture the exam timer and this stem about {topic}. "
            f"You need a clean decision, not a Wikipedia dump."
        )

    text2, c = BOILER_HOOK.subn(hook_repl, text)
    n += c
    text = text2

    # Doubled Watch out
    while "Watch out: Watch out:" in text:
        text = text.replace("Watch out: Watch out:", "Watch out:")
        n += 1

    # Doubled Remember
    while "Remember: Remember:" in text:
        text = text.replace("Remember: Remember:", "Remember:")
        n += 1

    # Tip leftover phrasing that became Watch out without substance
    text2 = text.replace(
        "Watch out: name the purpose or step the stem is asking for before you pick a brand-name tool. "
        "Tie it to a Boundry example when that helps memory.",
        "Watch out: picking a brand-name tool before you name the purpose the stem is testing.\n\n"
        "Remember: purpose first, product second. Boundry examples are memory hooks only.",
    )
    if text2 != text:
        n += 1
        text = text2

    # Explains that end abruptly without Remember (heuristic on Correct. lines)
    def ensure_remember_in_explain_strings(s: str) -> str:
        nonlocal n

        def one(m: re.Match[str]) -> str:
            nonlocal n
            body = m.group(1)
            if "Correct." not in body:
                return m.group(0)
            if "Remember:" in body:
                return m.group(0)
            n += 1
            fixed = body.rstrip(".") + ". Remember: match the control to what the stem shows."
            return '"' + fixed.replace('"', '\\"') + '"'

        # Only single-string explain values
        return re.sub(r'"(Correct\.[^"]*)"', one, s)

    text = ensure_remember_in_explain_strings(text)

    path.write_text(text, encoding="utf-8")
    ast.parse(text)
    return n


def main() -> None:
    for p in TARGETS:
        print(p.name, "fixes", fix(p))


if __name__ == "__main__":
    main()
