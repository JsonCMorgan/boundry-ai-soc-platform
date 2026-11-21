"""
Apply Boundry YouTube-tutor voice transforms to Sec+ Phase 1 generators.

Rewrites teach sections, practice/quiz explains, and PBQ coach text in:
  tools/gen_secplus_d2b.py, gen_secplus_d3.py, gen__secplus_d4.py, gen_secplus_d5.py
  (D1 is hand-authored to the new VOICE GUIDE.)

Does NOT change lesson IDs, answer indices, objectives, or unlock logic.
Run: python tools/_apply_youtube_tutor_voice.py
Then: python tools/build_secplus_phase1.py
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ROOT / "tools" / "gen_secplus_d2b.py",
    ROOT / "tools" / "gen_secplus_d3.py",
    ROOT / "tools" / "gen_secplus_d4.py",
    ROOT / "tools" / "gen_secplus_d5.py",
]

BOILER_FOCUS = re.compile(
    r"Exam focus:\s*master this for SY0-701 under time pressure\.\s*"
    r"Topic:\s*([^\n.]+)\.\s*",
    re.IGNORECASE,
)
BOILER_TIP = (
    "Exam tip: name the purpose or step the stem is asking for before you pick a "
    "brand-name tool. Tie it to a Boundry example when that helps memory."
)
GENERIC_EXPLAIN_TIP = (
    "Exam tip: eliminate answers that ignore containment, ownership, or the open path."
)
VOICE_HEADER = (
    'Voice: YouTube-tutor methods for SY0-701 '
    '(see VOICE GUIDE in build_secplus_phase1.py).'
)


def _fix_dashes(s: str) -> str:
    """Replace em/en dashes used as clause pivots with colon or comma patterns."""
    # Choice-style "Label — rest" → "Label: rest"
    s = re.sub(r"\s*[—–]\s*", ": ", s)
    # Collapse accidental double spaces
    s = re.sub(r"[ \t]{2,}", " ", s)
    return s


def _transform_section_body(body: str) -> str:
    """Rewrite one Show-me section body into YouTube-tutor beats."""
    text = textwrap_dedent_keep(body)
    text = _fix_dashes(text)

    # Kill D4/D5 boilerplate opener → Hook
    def _hook_from_topic(m: re.Match[str]) -> str:
        topic = m.group(1).strip()
        return (
            f"Hook: SY0-701 will pressure-test you on this: {topic}.\n\n"
        )

    text = BOILER_FOCUS.sub(_hook_from_topic, text)
    text = text.replace(BOILER_TIP, "").strip()

    # Classic markers → named techniques
    text = re.sub(r"(?im)^Exam focus:\s*", "Hook: ", text)
    text = re.sub(r"(?im)^Exam trick:\s*", "Watch out: ", text)
    text = re.sub(r"(?im)^Near-miss:\s*", "Watch out: ", text)
    text = re.sub(r"(?im)^Near-miss to avoid\s*", "Watch out: ", text)
    text = re.sub(r"(?im)^Exam tip:\s*", "Watch out: ", text)
    text = re.sub(r"(?im)^Anti-patterns\s*", "Watch out (anti-patterns):\n", text)

    # Ensure a Hook line exists near the top
    if not re.search(r"(?im)^Hook:", text):
        first = text.split("\n", 1)
        lead = first[0].strip()
        rest = first[1] if len(first) > 1 else ""
        if lead:
            text = f"Hook: {lead}\n\n{rest}".strip()
        else:
            text = f"Hook: Learn this cleanly for SY0-701.\n\n{text}".strip()

    # Ensure a Remember close if missing
    if not re.search(r"(?im)\bRemember:", text):
        text = (
            text.rstrip()
            + "\n\nRemember: when the stem matches this lesson, pick the control "
            "that closes the path or names the correct class. That is the exam ask."
        )

    # Light density cleanup: collapse 3+ blank lines
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def textwrap_dedent_keep(s: str) -> str:
    """Strip common indent without importing textwrap into transformed source."""
    import textwrap

    return textwrap.dedent(s).strip()


def _transform_explain(s: str) -> str:
    """Rewrite Help / Quiz / PBQ coach explain strings."""
    text = _fix_dashes(s.strip())
    text = text.replace(GENERIC_EXPLAIN_TIP, "").strip()
    text = re.sub(r"\s*Exam tip:\s*", " Watch out: ", text, flags=re.I)
    text = re.sub(r"\s*Exam trap:\s*", " Watch out: ", text, flags=re.I)

    if not text.startswith("Correct"):
        # PBQ coach lines sometimes start with "Correct mapping coach:"
        if text.lower().startswith("correct"):
            pass
        else:
            text = "Correct. " + text

    # Normalize "Correct mapping coach:" style
    text = re.sub(
        r"^Correct mapping coach:\s*",
        "Correct. ",
        text,
        flags=re.I,
    )

    if "Watch out:" not in text and "watch out:" not in text.lower():
        text = text.rstrip(".") + ". Watch out: near-miss answers that ignore the stem's path or control class."

    if "Remember:" not in text:
        text = text.rstrip(".") + ". Remember: match the control to what the stem actually shows."

    # Cleanup doubled spaces / repeated periods
    text = re.sub(r"\.\s*\.", ".", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _transform_file(path: Path) -> tuple[int, int]:
    """Transform one generator file. Returns (sections_touched, explains_touched)."""
    raw = path.read_text(encoding="utf-8")
    sections = 0
    explains = 0

    # Header voice line
    raw = re.sub(
        r"Voice:.*?(?=\nSee VOICE GUIDE|\n\"\"\")",
        VOICE_HEADER + "\n",
        raw,
        count=1,
        flags=re.S,
    )
    if "YouTube-tutor" not in raw[:400]:
        raw = raw.replace(
            'See VOICE GUIDE in tools/build_secplus_phase1.py.',
            VOICE_HEADER + "\nSee VOICE GUIDE in tools/build_secplus_phase1.py.",
            1,
        )

    # Triple-quoted section bodies that follow heading tuples: ("title", """ ... """)
    # Also transform explain= and "explain": strings carefully.

    def repl_triple(m: re.Match[str]) -> str:
        nonlocal sections
        quote = m.group(1)
        body = m.group(2)
        # Skip tiny strings / imports
        if len(body.strip()) < 80:
            return m.group(0)
        # Skip module docstring (file starts with it) by requiring Hook/Exam/ops content cues
        cues = ("Exam focus", "Exam tip", "Remember", "Boundry", "SY0", "Hook", "Watch out")
        if not any(c in body for c in cues):
            return m.group(0)
        new_body = _transform_section_body(body)
        sections += 1
        # Re-indent body lines with 16 spaces to match generator style
        indented = "\n".join(
            ("                " + line if line.strip() else "")
            for line in new_body.splitlines()
        )
        return f"{quote}\n{indented}\n                {quote}"

    # Only transform bodies that look like lesson sections (contain Exam/Remember/Boundry)
    raw2 = re.sub(
        r'("""|\'\'\')\n(.*?)(\1)',
        lambda m: repl_triple(m) if len(m.group(2)) > 80 else m.group(0),
        raw,
        flags=re.S,
    )

    # Transform explain keyword arguments: explain="..." or explain=( "..." )
    def repl_explain_dq(m: re.Match[str]) -> str:
        nonlocal explains
        prefix, body, suffix = m.group(1), m.group(2), m.group(3)
        if "Correct" not in body and "mapping coach" not in body.lower():
            # Still transform if it is a short explain without Correct
            if len(body) < 20:
                return m.group(0)
        explains += 1
        new = _transform_explain(body)
        # Escape quotes in new text
        new = new.replace('\\', '\\\\').replace('"', '\\"')
        return f'{prefix}{new}{suffix}'

    # Single-line explain="..."
    raw2 = re.sub(
        r'(explain\s*=\s*")((?:\\.|[^"\\])*)(")',
        repl_explain_dq,
        raw2,
    )
    # "explain": "..." in PBQ dicts
    raw2 = re.sub(
        r'("explain"\s*:\s*")((?:\\.|[^"\\])*)(")',
        repl_explain_dq,
        raw2,
    )

    # Multi-line explain concatenated with adjacent string literals after Correct.
    # Pattern: "Correct. ... "\n                "more..."
    # Leave those; build step will still work. Transform first segment only (done above).

    # Parenthesized multi-line explain=( "a" "b" )
    def repl_explain_paren(m: re.Match[str]) -> str:
        nonlocal explains
        inner = m.group(1)
        parts = re.findall(r'"((?:\\.|[^"\\])*)"', inner)
        if not parts:
            return m.group(0)
        joined = "".join(bytes(p, "utf-8").decode("unicode_escape") if False else p.replace('\\"', '"') for p in parts)
        # Simpler join without escape games:
        joined = "".join(p.replace('\\"', '"').replace("\\n", "\n") for p in parts)
        explains += 1
        new = _transform_explain(joined)
        # Keep as two soft lines if long
        if len(new) > 110:
            cut = new.rfind(" ", 0, 100)
            if cut < 40:
                cut = 100
            a, b = new[:cut].rstrip(), new[cut:].lstrip()
            a = a.replace('"', '\\"')
            b = b.replace('"', '\\"')
            return f'explain=(\n                "{a} "\n                "{b}",\n            )'
        new = new.replace('"', '\\"')
        return f'explain="{new}"'

    raw2 = re.sub(
        r"explain\s*=\s*\(\s*((?:\"(?:\\.|[^\"\\])*\"\s*)+)\)",
        repl_explain_paren,
        raw2,
        flags=re.S,
    )

    # Same for "explain": ( "a" "b" )
    def repl_explain_paren_key(m: re.Match[str]) -> str:
        nonlocal explains
        inner = m.group(1)
        parts = re.findall(r'"((?:\\.|[^"\\])*)"', inner)
        if not parts:
            return m.group(0)
        joined = "".join(p.replace('\\"', '"') for p in parts)
        explains += 1
        new = _transform_explain(joined)
        if len(new) > 110:
            cut = new.rfind(" ", 0, 100)
            if cut < 40:
                cut = 100
            a, b = new[:cut].rstrip(), new[cut:].lstrip()
            a = a.replace('"', '\\"')
            b = b.replace('"', '\\"')
            return f'"explain": (\n            "{a} "\n            "{b}"\n        )'
        new = new.replace('"', '\\"')
        return f'"explain": "{new}"'

    raw2 = re.sub(
        r'"explain"\s*:\s*\(\s*((?:\"(?:\\.|[^\"\\])*\"\s*)+)\)',
        repl_explain_paren_key,
        raw2,
        flags=re.S,
    )

    # Fix choice em dashes that remain outside explains
    raw2 = re.sub(r'(\["[^"]*?)\s*[—–]\s*', r"\1: ", raw2)
    raw2 = re.sub(r'(,"[^"]*?)\s*[—–]\s*', r"\1: ", raw2)

    path.write_text(raw2, encoding="utf-8")
    return sections, explains


def main() -> None:
    """Apply voice transforms to D2–D5 generators."""
    total_s = total_e = 0
    for path in TARGETS:
        if not path.exists():
            print("MISSING", path)
            continue
        s, e = _transform_file(path)
        total_s += s
        total_e += e
        print(f"{path.name}: sections~{s} explains~{e}")
    print(f"TOTAL sections~{total_s} explains~{total_e}")
    print("Next: python tools/build_secplus_phase1.py && python tests/test_secplus.py")


if __name__ == "__main__":
    main()
