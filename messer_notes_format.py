"""Render Messer course-note plain text as HTML (structure only, text unchanged)."""

from __future__ import annotations

import html
import re


def _strip_bullet_prefix(line: str) -> tuple[str | None, str]:
    """
    Return (kind, content) where kind is 'top', 'sub', or None for plain lines.
    Does not alter words inside content.
    """
    if re.match(r"^\t+[–\-]", line) or re.match(r"^[\t ]{2,}[–\-]\s", line):
        content = re.sub(r"^[\t ]+[–\-]\s*", "", line)
        return "sub", content
    if re.match(r"^[\t ]*[•\u2022\u274d]\s*", line):
        content = re.sub(r"^[\t ]*[•\u2022\u274d]\s*", "", line)
        return "top", content
    return None, line.strip()


def format_notes_body(text: str, mode: str = "notes") -> str:
    """
    Convert PDF extract newlines/bullets to headings and lists.
    mode: 'notes' (Course notes) or 'transcript' (paragraph style for plain lines).
    """
    if not (text or "").strip():
        return ""

    lines = text.splitlines()
    chunks: list[str] = []
    in_outer = False
    in_inner = False
    in_li = False

    def close_inner() -> None:
        nonlocal in_inner
        if in_inner:
            chunks.append("</ul>")
            in_inner = False

    def close_li() -> None:
        nonlocal in_li
        close_inner()
        if in_li:
            chunks.append("</li>")
            in_li = False

    def close_outer() -> None:
        nonlocal in_outer
        close_li()
        if in_outer:
            chunks.append("</ul>")
            in_outer = False

    for line in lines:
        if not line.strip():
            close_outer()
            chunks.append('<div class="notes-spacer" aria-hidden="true"></div>')
            continue

        kind, content = _strip_bullet_prefix(line)
        content = html.escape(content)

        if kind == "sub":
            if not in_outer:
                chunks.append('<ul class="notes-list">')
                in_outer = True
            if not in_li:
                chunks.append("<li>")
                in_li = True
            if not in_inner:
                chunks.append('<ul class="notes-sublist">')
                in_inner = True
            chunks.append(f"<li>{content}</li>")
            continue

        if kind == "top":
            close_li()
            if not in_outer:
                chunks.append('<ul class="notes-list">')
                in_outer = True
            chunks.append(f"<li>{content}")
            in_li = True
            continue

        close_outer()
        if mode == "transcript":
            chunks.append(f'<p class="notes-p">{content}</p>')
        else:
            chunks.append(f'<h3 class="notes-heading">{content}</h3>')

    close_outer()
    return f'<div class="notes-readable">{"".join(chunks)}</div>'
