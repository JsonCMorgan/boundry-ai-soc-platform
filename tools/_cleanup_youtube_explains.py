"""Second pass: normalize explains + kill leftover Exam tip / em dashes in D2–D5 gens."""
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

GENERIC = (
    "Exam tip: eliminate answers that ignore containment, ownership, or the open path."
)
GENERIC2 = (
    "eliminate answers that ignore containment, ownership, or the open path."
)


def polish_explain(s: str) -> str:
    """Force Help/Quiz/PBQ explain into Correct / Watch out / Remember shape."""
    t = s.strip()
    t = t.replace("—", ": ").replace("–", ": ")
    t = t.replace(GENERIC, "").strip()
    t = re.sub(r"(?i)\bExam tip:\s*", "Watch out: ", t)
    t = re.sub(r"(?i)\bExam trap:\s*", "Watch out: ", t)
    t = re.sub(r"(?i)\bExam focus:\s*", "Hook: ", t)
    t = re.sub(r"(?i)Correct mapping coach:\s*", "Correct. ", t)
    if GENERIC2 in t:
        t = t.replace(GENERIC2, "answers that ignore containment, ownership, or the open path")
    if not re.match(r"(?i)^correct\b", t):
        t = "Correct. " + t
    if "Watch out:" not in t:
        t = t.rstrip(".") + ". Watch out: near-miss answers that ignore the stem's path or control class."
    if "Remember:" not in t:
        t = t.rstrip(".") + ". Remember: match the control to what the stem actually shows."
    t = re.sub(r"\s{2,}", " ", t)
    t = re.sub(r"\.\s*\.", ".", t)
    return t.strip()


def rewrite_joined_strings(node_src: str) -> str | None:
    """If node_src is a string or implicitly joined strings, polish explain text."""
    try:
        tree = ast.parse(node_src)
    except SyntaxError:
        return None
    if not tree.body or not isinstance(tree.body[0], ast.Expr):
        return None
    val = tree.body[0].value
    parts: list[str] = []
    if isinstance(val, ast.Constant) and isinstance(val.value, str):
        parts = [val.value]
    elif isinstance(val, ast.BinOp):
        return None
    elif isinstance(val, ast.JoinedStr):
        return None
    else:
        # Python 3.12+ may not use BinOp for adjacent; adjacent are just one Constant in some cases
        return None
    if not parts:
        return None
    new = polish_explain("".join(parts))
    return json_escape(new)


def json_escape(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def transform(path: Path) -> int:
    """Rewrite explain= / 'explain': string groups in source text."""
    src = path.read_text(encoding="utf-8")
    n = 0

    # em dashes anywhere in file (choices, text)
    if re.search(r"[—–]", src):
        src2 = re.sub(r"\s*[—–]\s*", ": ", src)
        if src2 != src:
            n += src.count("—") + src.count("–")
            src = src2

    # Replace remaining Exam tip / trap phrases in whole file (explains + leftovers)
    def tip_repl(m: re.Match[str]) -> str:
        nonlocal n
        n += 1
        kind = m.group(1).lower()
        if "trap" in kind or "tip" in kind:
            return "Watch out: "
        return "Hook: "

    src = re.sub(r"\bExam (tip|trap|focus):\s*", tip_repl, src, flags=re.I)

    # Polish explain=("""...""") and explain="..." and multi-line concatenations
    pattern = re.compile(
        r'(explain\s*=\s*)(?:\(\s*)?((?:"(?:\\.|[^"\\])*"\s*)+)(?:\))?',
        re.S,
    )

    def expl_repl(m: re.Match[str]) -> str:
        nonlocal n
        prefix = m.group(1)
        blob = m.group(2)
        parts = re.findall(r'"((?:\\.|[^"\\])*)"', blob)
        if not parts:
            return m.group(0)
        joined = "".join(
            bytes(p, "utf-8").decode("unicode_escape")
            if False
            else codecs_decode(p)
            for p in parts
        )
        new = polish_explain(joined)
        n += 1
        esc = new.replace("\\", "\\\\").replace('"', '\\"')
        if len(esc) <= 100:
            return f'{prefix}"{esc}"'
        # split into two adjacent strings for readability
        cut = esc.rfind(" ", 0, 90)
        if cut < 30:
            cut = 90
        a, b = esc[:cut].rstrip(), esc[cut:].lstrip()
        return f'{prefix}(\n                "{a} "\n                "{b}"\n            )'

    def codecs_decode(p: str) -> str:
        return (
            p.replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace('\\"', '"')
            .replace("\\\\", "\\")
        )

    src = pattern.sub(expl_repl, src)

    pattern2 = re.compile(
        r'("explain"\s*:\s*)(?:\(\s*)?((?:"(?:\\.|[^"\\])*"\s*)+)(?:\))?',
        re.S,
    )

    def expl_repl2(m: re.Match[str]) -> str:
        nonlocal n
        prefix = m.group(1)
        blob = m.group(2)
        parts = re.findall(r'"((?:\\.|[^"\\])*)"', blob)
        if not parts:
            return m.group(0)
        joined = "".join(
            p.replace("\\n", "\n").replace('\\"', '"').replace("\\\\", "\\")
            for p in parts
        )
        new = polish_explain(joined)
        n += 1
        esc = new.replace("\\", "\\\\").replace('"', '\\"')
        if len(esc) <= 100:
            return f'{prefix}"{esc}"'
        cut = esc.rfind(" ", 0, 90)
        if cut < 30:
            cut = 90
        a, b = esc[:cut].rstrip(), esc[cut:].lstrip()
        return f'{prefix}(\n            "{a} "\n            "{b}"\n        )'

    src = pattern2.sub(expl_repl2, src)

    # Kill leftover generic phrase if still present without Exam tip prefix
    if GENERIC2 in src and "Watch out: answers that ignore" not in src:
        src = src.replace(
            GENERIC2,
            "Watch out: answers that ignore containment, ownership, or the open path",
        )

    path.write_text(src, encoding="utf-8")
    return n


def main() -> None:
    for path in TARGETS:
        n = transform(path)
        try:
            ast.parse(path.read_text(encoding="utf-8"))
            ok = "OK"
        except SyntaxError as e:
            ok = f"FAIL {e}"
        print(path.name, "edits~", n, ok)


if __name__ == "__main__":
    main()
