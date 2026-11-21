#!/usr/bin/env python3
"""
Scan templates for <textarea> without a stacked writing coach.

In-scope textareas must have either:
  - a .writing-coach block within LOOKBACK lines above, or
  - data-writing-coach="coach_id" on the textarea (JS-rendered fields).

Excluded templates (auth, search-only, partial itself):
  login, register, 2fa, password reset, _writing_coach.html
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"

LOOKBACK = 25

EXCLUDE_FILES = {
    "_writing_coach.html",
    "login.html",
    "register.html",
    "two_factor.html",
    "2fa.html",
    "reset_password.html",
    "forgot_password.html",
}

EXCLUDE_PATH_PARTS = ("auth",)


def _should_skip(path: Path) -> bool:
    if path.name in EXCLUDE_FILES:
        return True
    parts = {p.lower() for p in path.parts}
    if parts & set(EXCLUDE_PATH_PARTS):
        return True
    return False


def _textarea_openings(text: str) -> list[tuple[int, str]]:
    """Return (1-based line number of <textarea, full opening tag text) pairs."""
    out: list[tuple[int, str]] = []
    for m in re.finditer(r"<textarea\b[^>]*(?:>|(?:\s[^>]*)>)", text, flags=re.I | re.S):
        line = text[: m.start()].count("\n") + 1
        out.append((line, m.group(0)))
    # Multiline opening tags (attributes span lines)
    for m in re.finditer(r"<textarea\b", text, flags=re.I):
        start = m.start()
        end = text.find(">", start)
        if end == -1:
            continue
        chunk = text[start : end + 1]
        if "\n" in chunk:
            line = text[:start].count("\n") + 1
            if not any(line == ln for ln, _ in out):
                out.append((line, chunk))
    return sorted(set(out), key=lambda x: x[0])


def audit_file(text: str, rel: str) -> list[str]:
    """Return violation messages for one template."""
    lines = text.splitlines()
    violations: list[str] = []
    for i, opening in _textarea_openings(text):
        if 'data-writing-coach="' in opening or "data-writing-coach='" in opening:
            continue
        start = max(0, i - 1 - LOOKBACK)
        window = "\n".join(lines[start : i])
        if "writing-coach" in window or "WritingCoach.buildHtml" in window:
            continue
        violations.append(
            f"{rel}:{i}: textarea missing coach (no .writing-coach in prior {LOOKBACK} lines, no data-writing-coach)"
        )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit writing coach coverage on textareas.")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any violations.")
    args = parser.parse_args()

    all_violations: list[str] = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        if _should_skip(path):
            continue
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        all_violations.extend(audit_file(text, rel))

    if all_violations:
        print(f"Writing coach audit: {len(all_violations)} issue(s)\n")
        for v in all_violations:
            print(v)
    else:
        print("Writing coach audit: OK (no missing coaches on in-scope textareas)")

    if args.strict and all_violations:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
