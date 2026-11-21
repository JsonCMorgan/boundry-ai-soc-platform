"""Readable Help-me / hint text (structured for UI, not one wall of text)."""

from __future__ import annotations

import re
from typing import Any


def _sentences(text: str) -> list[str]:
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t:
        return []
    parts = re.split(r"(?<=[.!?])\s+", t)
    return [p.strip() for p in parts if p.strip()]


def _paragraphize(sentences: list[str], target_len: int = 130) -> list[str]:
    """Group sentences into short paragraphs for scanning."""
    if not sentences:
        return []
    out: list[str] = []
    buf = ""
    for s in sentences:
        if not buf:
            buf = s
            continue
        if len(buf) + 1 + len(s) <= target_len:
            buf = f"{buf} {s}"
        else:
            out.append(buf)
            buf = s
    if buf:
        out.append(buf)
    return out


def split_term_and_body(text: str, fallback_term: str = "") -> tuple[str, str]:
    """Split 'Deterrent — definition...' into term + body."""
    raw = re.sub(r"\s+", " ", (text or "").strip())
    if not raw:
        return fallback_term, ""
    for sep in (" — ", " – ", " - "):
        if sep in raw:
            left, right = raw.split(sep, 1)
            term = left.strip() or fallback_term
            return term, right.strip()
    return fallback_term or raw, raw if fallback_term else ""


def format_reading_block(text: str, *, fallback_term: str = "", role: str = "") -> dict[str, Any]:
    """Structured block for accordion bodies and hints."""
    term, body = split_term_and_body(text, fallback_term)
    if not body and term and term != fallback_term:
        body = term
        term = fallback_term or term
    lines = _paragraphize(_sentences(body))
    if not lines and body:
        lines = [body]
    role_note = ""
    if role == "your_pick":
        role_note = "Why your pick misses this scenario"
    elif role == "other_wrong":
        role_note = "Why this option is wrong here"
    elif role == "correct":
        role_note = "Why this is the best answer"
    return {
        "term": term,
        "lines": lines,
        "role_note": role_note,
    }


def format_lead_block(lead: str) -> dict[str, Any]:
    """Split review lead into headline + follow-up line when possible."""
    raw = re.sub(r"\s+", " ", (lead or "").strip())
    if not raw:
        return {"headline": "", "sub": ""}
    if ". Start with" in raw:
        headline, sub = raw.split(". Start with", 1)
        return {"headline": headline.strip() + ".", "sub": "Start with" + sub.strip()}
    if ". Then " in raw:
        headline, sub = raw.split(". Then ", 1)
        return {"headline": headline.strip() + ".", "sub": "Then " + sub.strip()}
    sentences = _sentences(raw)
    if len(sentences) >= 2:
        return {"headline": sentences[0], "sub": " ".join(sentences[1:])}
    return {"headline": raw, "sub": ""}
