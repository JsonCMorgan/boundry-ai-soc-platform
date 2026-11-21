"""
Turn Messer course-note extracts into professor-style Show-me lessons (local only).

Tier 1: structural rewrite (always, no cloud).
Tier 2: optional Ollama polish (tools/messer_format_lessons.py).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from messer_paths import messer_work_dir

_BULLET = re.compile(r"^[\u2022\u2023\ufffd•\-]\s*(.+)$")
_DOMAIN_WORK = {
    "d1_concepts": "You see this when someone asks what kind of control something is, or when policy language shows up in a ticket.",
    "d2_threats": "You see this when alerts, IOCs, or user reports describe how an attack started or what failed.",
    "d3_architecture": "You see this when a design choice must limit blast radius: segmentation, cloud shared responsibility, or data handling.",
    "d4_operations": "You see this on shift: logs, IAM changes, vuln tickets, IR steps, or hardening tasks.",
    "d5_oversight": "You see this when risk, vendors, compliance, or awareness training show up in meetings and audits.",
}


def formatted_sidecar_path(lesson_id: str) -> Path:
    return messer_work_dir() / "curriculum" / "formatted" / f"{lesson_id}.json"


def load_formatted_sidecar(lesson_id: str) -> dict[str, Any] | None:
    p = formatted_sidecar_path(lesson_id)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _clean_notes(body: str) -> str:
    body = re.sub(r"\x08", "", body or "")
    body = re.sub(r"https?://\S+", "", body)
    body = re.sub(r"Professor Messer[^\n]*", "", body, flags=re.I)
    body = re.sub(r"©\s*\d{4}[^\n]*", "", body)
    return body.strip()


def _sentence(s: str) -> str:
    s = re.sub(r"\s+", " ", (s or "").strip())
    if not s:
        return ""
    if s[-1] not in ".!?":
        s += "."
    return s


def _detail_to_sentence(detail: str) -> str:
    d = detail.strip()
    if not d:
        return ""
    low = d.lower()
    if low.startswith(("block ", "prevent ", "limit ", "find ", "apply ", "enable ", "review ", "collect ")):
        return _sentence(d[0].upper() + d[1:] if d else d)
    return _sentence(f"For example, {d.lower()}" if d[0].islower() else d)


def _parse_blocks(body: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in body.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        is_sub = raw.startswith("\t") or raw.startswith("    ")
        bullet = _BULLET.match(stripped)
        if not is_sub and not bullet and re.match(r"^[A-Za-z][A-Za-z0-9 \-/()]{2,72}$", stripped):
            if current:
                blocks.append(current)
            current = {"title": stripped, "items": []}
            continue
        if current is None:
            current = {"title": "", "items": []}
        if bullet and not is_sub:
            current["items"].append({"head": bullet.group(1).strip(), "details": []})
        elif is_sub and bullet and current["items"]:
            current["items"][-1]["details"].append(bullet.group(1).strip())
    if current and (current.get("title") or current.get("items")):
        blocks.append(current)
    return blocks


def _block_to_paragraph(block: dict[str, Any]) -> str:
    parts: list[str] = []
    title = (block.get("title") or "").strip()
    if title:
        parts.append(_sentence(f"Next, {title}" if not title.endswith(".") else title))
    for item in block.get("items") or []:
        head = (item.get("head") or "").strip()
        details = item.get("details") or []
        if not head:
            continue
        if details:
            support = " ".join(_detail_to_sentence(d) for d in details[:4] if d)
            parts.append(_sentence(f"{head} {support}" if support else head))
        else:
            parts.append(_sentence(head))
    return "\n\n".join(parts)


def _define_terms_paragraph(title: str, terms: list[str]) -> str:
    if not terms:
        return (
            f"In this session we work on {title.lower()}. "
            "When a word is new, say it out loud once and tie it to something you would see on a ticket or in a log."
        )
    picks = terms[:5]
    lines = [
        "Before we go deeper, anchor a few labels from the notes:",
        "",
    ]
    for t in picks:
        lines.append(f"• {t}: say what it is in one plain sentence, then give one example.")
    return "\n".join(lines)


def build_structured_lesson(
    *,
    title: str,
    objective_ref: str,
    domain_id: str,
    notes_body: str,
    key_terms: list[str],
    messer_session: str,
) -> dict[str, Any]:
    """Professor-shaped lesson from raw notes (no AI)."""
    clean = _clean_notes(notes_body)
    blocks = _parse_blocks(clean)
    work = _DOMAIN_WORK.get(domain_id, _DOMAIN_WORK["d1_concepts"])

    orient = (
        "You are studying for CompTIA Security+. CompTIA names the current exam version SY0-701. "
        "In this lab, when I say \"the exam,\" I mean that Security+ exam.\n\n"
        f"Today we cover {title} (objective {objective_ref or 'from the 701 outline'}, "
        f"session {messer_session}). "
        "I am going to teach this the way I would in a classroom: orient, define, then specifics you can reuse on the exam and on a junior SOC desk."
    )

    sections: list[dict[str, str]] = [
        {"heading": "What we are doing today", "body": orient},
        {
            "heading": "Where you will use this",
            "body": _sentence(work),
        },
        {
            "heading": "Terms to lock in first",
            "body": _define_terms_paragraph(title, key_terms),
        },
    ]

    for block in blocks[:6]:
        para = _block_to_paragraph(block)
        if len(para) < 40:
            continue
        heading = (block.get("title") or "Core ideas").strip()
        if len(heading) > 60:
            heading = heading[:57] + "..."
        sections.append({"heading": heading, "body": para})

    if len(sections) < 4 and clean:
        sections.append({
            "heading": "From the notes",
            "body": re.sub(r"\t+", " ", clean)[:4500],
        })

    exam_steps = (
        "How to answer on exam day:\n"
        "1. Read the question twice and underline the job word (prevent, detect, correct, and so on).\n"
        "2. Match the scenario to the definition, not to a tool brand you recognize.\n"
        "3. Eliminate answers that solve the wrong problem (policy vs technical, or vice versa).\n"
        "4. Pick the best fit, then sanity-check: would this control actually work in the story?"
    )
    sections.append({"heading": "How to answer on exam day", "body": exam_steps})

    trap = (
        f"A common trap on {title.lower()} questions is choosing an answer that sounds secure but addresses "
        "the wrong control function or the wrong layer (managerial vs technical, or preventive vs detective). "
        "Ask: what job must this control do in the scenario?"
    )
    sections.append({"heading": "Common trap", "body": trap})

    remember = (
        f"Remember: for {title.lower()}, name the idea first, then map it to what the question is asking the control to do."
    )
    sections.append({"heading": "Remember", "body": remember})

    define_first = []
    for term in key_terms[:3]:
        define_first.append({
            "term": term,
            "say": f"{term} means [your one-sentence definition] in the context of {title.lower()}.",
        })

    teach_back = {
        "listener_prompt": f"Can you walk me through {title.lower()} like I am new to security?",
        "explain_aloud": (
            f"In about 60 seconds: define the main idea for {title.lower()}, "
            "give one desk example, and name one exam trap to avoid."
        ),
        "define_first": define_first,
        "desk_one_liner": work,
        "exam_trap": trap,
        "remember": remember,
    }

    goal = f"Explain {title.lower()} in plain English and classify exam scenarios without mixing control types."

    return {
        "sections": sections,
        "teach_back": teach_back,
        "goal": goal,
        "format": "structured",
    }


def merge_formatted_into_lesson(lesson: dict[str, Any], formatted: dict[str, Any]) -> dict[str, Any]:
    """Apply sidecar or structured output onto a curriculum lesson row."""
    out = dict(lesson)
    if formatted.get("sections"):
        out["sections"] = formatted["sections"]
    if formatted.get("teach_back"):
        out["teach_back"] = formatted["teach_back"]
    if formatted.get("goal"):
        out["goal"] = formatted["goal"]
    out["lesson_format"] = formatted.get("format") or formatted.get("source") or "unknown"
    return out


def build_lesson_content(
    *,
    lesson_id: str,
    title: str,
    objective_ref: str,
    domain_id: str,
    notes_body: str,
    key_terms: list[str],
    messer_session: str,
) -> dict[str, Any]:
    """Prefer Ollama sidecar, else structured professor rewrite."""
    sidecar = load_formatted_sidecar(lesson_id)
    if sidecar and sidecar.get("sections"):
        return sidecar
    return build_structured_lesson(
        title=title,
        objective_ref=objective_ref,
        domain_id=domain_id,
        notes_body=notes_body,
        key_terms=key_terms,
        messer_session=messer_session,
    )
