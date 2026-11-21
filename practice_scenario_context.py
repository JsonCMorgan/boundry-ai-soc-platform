"""Define the scenario object in the question before grading control-type answers."""

from __future__ import annotations

import re
from typing import Any

from practice_hints import _scenario_hook
from practice_text_format import format_reading_block

# Tutor fallbacks when course notes do not name the object (define before use).
KNOWN_SCENARIO: dict[str, str] = {
    "login banner": (
        "A login banner is the message users see before they sign in to a system. "
        "It usually states authorized-use rules, monitoring, and legal notice. "
        "It does not block access by itself; it warns people and can discourage misuse."
    ),
    "application splash screen": (
        "An application splash screen is the first screen or popup when software starts. "
        "If it warns about policy or monitoring, it discourages misuse without blocking the app."
    ),
    "posted warning sign": (
        "A posted warning sign tells people rules or consequences (for example authorized "
        "personnel only). It discourages bad behavior but does not physically stop entry."
    ),
    "firewall rule": (
        "A firewall rule is a allow or deny instruction on network traffic (ports, IPs, apps). "
        "When it blocks traffic before a connection completes, it is acting as a preventive control."
    ),
    "badge reader": (
        "A badge reader checks credentials at a door. It limits who can enter a space, "
        "so it is a physical access control."
    ),
    "security guards": (
        "Security guards are people who watch a site and respond to incidents. "
        "That is an operational control, not something built into software alone."
    ),
    "ips": (
        "An IPS (intrusion prevention system) watches traffic and can alert, log, and block "
        "suspicious patterns. Detection and blocking can map to detective and preventive roles."
    ),
    "siem": (
        "A SIEM collects and correlates logs from many systems so analysts can detect patterns. "
        "It is primarily detective: it shows you what happened."
    ),
    "restoring from backups": (
        "Restoring from backups returns systems or data to a known-good state after damage. "
        "That fixes impact after an event, which is corrective."
    ),
    "corporate security policies": (
        "Corporate security policies are written rules (acceptable use, data handling, etc.). "
        "They tell people what to do, which is directive control at the policy layer."
    ),
    "security awareness training": (
        "Security awareness training teaches users how to behave safely (phishing, passwords, reporting). "
        "It directs people toward compliance rather than blocking a port or logging an event."
    ),
}


def _normalize_key(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _known_definition(focus: str) -> str:
    key = _normalize_key(focus)
    if key in KNOWN_SCENARIO:
        return KNOWN_SCENARIO[key]
    for phrase, defn in KNOWN_SCENARIO.items():
        if phrase in key or key in phrase:
            return defn
    if "banner" in key and "login" in key:
        return KNOWN_SCENARIO["login banner"]
    if "banner" in key:
        return KNOWN_SCENARIO["login banner"]
    if "firewall" in key:
        return KNOWN_SCENARIO["firewall rule"]
    if "backup" in key or "restore" in key:
        return KNOWN_SCENARIO["restoring from backups"]
    return ""


def _notes_body(lesson: dict[str, Any] | None) -> str:
    if not lesson:
        return ""
    for sec in lesson.get("sections") or []:
        if (sec.get("heading") or "").lower() == "course notes":
            return sec.get("body") or ""
    return ""


def _snippet_from_notes(focus: str, lesson: dict[str, Any] | None) -> str:
    body = _notes_body(lesson)
    if not body:
        return ""
    focus_words = set(re.findall(r"[a-z0-9]{4,}", focus.lower()))
    best_line = ""
    best_score = 0
    for line in body.splitlines():
        clean = line.strip().lstrip("•\t–- ")
        if len(clean) < 24:
            continue
        low = clean.lower()
        score = sum(1 for w in focus_words if w in low)
        if score > best_score:
            best_score = score
            best_line = clean
    if best_score > 0:
        return re.sub(r"\s+", " ", best_line)
    if "banner" in focus.lower():
        for line in body.splitlines():
            low = line.lower()
            if "splash" in low or "warning sign" in low:
                return (
                    "Your course notes group application splash screens and posted warning signs "
                    "under deterrent controls. A login banner is the same idea on a sign-in screen."
                )
    return ""


def build_scenario_context(
    prompt: str,
    lesson_id: str | None = None,
) -> dict[str, Any] | None:
    """Return UI block defining what the question refers to, or None if empty."""
    focus = _scenario_hook(prompt)
    if not focus:
        return None

    lesson = None
    if lesson_id:
        try:
            import secplus_learn

            lesson = secplus_learn.get_lesson(lesson_id)
        except Exception:
            lesson = None

    parts: list[str] = []
    known = _known_definition(focus)
    if known:
        parts.append(known)
    notes = _snippet_from_notes(focus, lesson)
    if notes and notes not in (known or ""):
        parts.append(notes)

    if not parts:
        parts.append(
            f"The question is asking about {focus}. "
            "State in plain words what that is in the scenario before you classify the control."
        )

    text = " ".join(parts)
    formatted = format_reading_block(text, fallback_term=focus, role="scenario")
    formatted["role_note"] = "What the question is about"
    return {
        "title": "What the question is about",
        "term": focus,
        "text": text,
        "formatted": formatted,
    }
