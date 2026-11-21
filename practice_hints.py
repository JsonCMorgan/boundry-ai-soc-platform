"""Tailored Help-me memory hooks (tutor voice, one question at a time)."""

from __future__ import annotations

import json
import re
from typing import Any

GENERIC_HINT = "Re-read the course notes for this session."


def _clean_more_info(text: str) -> str:
    """Drop Messer PDF tail noise (links, exam headers) from More information blocks."""
    t = re.sub(r"\s+", " ", (text or "").strip())
    if not t:
        return ""
    t = re.sub(r"https?://\S+", "", t).strip()
    low = t.lower()
    if "practice exam" in low and "answers" in low:
        return ""
    if re.match(r"^SY0-\d+,\s*Objective", t, re.I):
        return ""
    if len(t) < 24:
        return ""
    return t


def _shorten(text: str, max_len: int) -> str:
    t = re.sub(r"\s+", " ", (text or "").strip())
    if len(t) <= max_len:
        return t
    cut = t[: max_len - 3].rsplit(" ", 1)[0]
    return cut + "..."


def _scenario_hook(prompt: str) -> str:
    """Pull the scenario object from the question stem."""
    p = (prompt or "").strip().rstrip("?")
    patterns = (
        r"associated with (?:a |an |the )?(.+)$",
        r"related to (?:a |an |the )?(.+)$",
        r"(?:for|with|when using|when|involving|during)\s+(?:a |an |the )?(.+)$",
        r"example of (?:a |an |the )?(.+)$",
        r"which (?:type|kind) of (.+?) (?:is|would|should|best)",
    )
    for pat in patterns:
        m = re.search(pat, p, re.I)
        if m:
            return _shorten(m.group(1).strip(), 72)
    words = p.split()
    if len(words) >= 5:
        return _shorten(" ".join(words[-6:]), 72)
    return _shorten(p, 72)


def _definition_snip(correct_label: str, correct_explain: str) -> str:
    explain = re.sub(r"\s+", " ", (correct_explain or "").strip())
    if not explain:
        return ""
    for sep in (" — ", " - ", "–"):
        if sep in explain:
            parts = explain.split(sep, 1)
            if len(parts) == 2 and parts[1].strip():
                return _shorten(parts[1].strip(), 160)
    if correct_label and correct_label.lower() in explain.lower():
        tail = explain.split(correct_label, 1)[-1].strip(" .,:;-")
        if tail:
            return _shorten(tail, 160)
    return _shorten(explain, 160)


def _more_info_from_item(item: dict[str, Any]) -> str:
    raw = (item.get("more_info") or "").strip()
    if raw:
        return raw
    prov = item.get("provenance") or item.get("provenance_json")
    if isinstance(prov, str):
        try:
            prov = json.loads(prov)
        except json.JSONDecodeError:
            prov = {}
    if isinstance(prov, dict):
        return (prov.get("more_info") or "").strip()
    return ""


def build_practice_hint(
    *,
    prompt: str,
    choices: list[str],
    answer_idx: int,
    correct_explain: str = "",
    more_info: str = "",
) -> str:
    """One tailored memory hook for Hint button and wrong-answer nudges."""
    if answer_idx < 0 or answer_idx >= len(choices):
        return "Match the scenario to the control or concept the question names."

    label = choices[answer_idx]
    scenario = _scenario_hook(prompt)
    extra = _clean_more_info(more_info)
    if extra:
        hook = _shorten(extra, 200)
        if scenario:
            return f"Remember: {scenario} points to {label.lower()}. {hook}"
        return f"Remember: {hook}"

    defn = _definition_snip(label, correct_explain)
    label_l = label.lower()

    if "control" in (prompt or "").lower() and scenario:
        if defn:
            return (
                f"Memory hook: {scenario} is about what the control does in this scene, "
                f"not the tool category. Here that is {label_l}: {defn}"
            )
        return (
            f"Memory hook: ask what job the control does for \"{scenario}\" "
            f"(stop, watch, fix, warn, backup plan, or tell people). "
            f"This question wants {label_l}."
        )

    if scenario and defn:
        return f"On the exam, tie \"{scenario}\" to {label_l}. {defn}"

    if defn:
        return f"Lock in {label_l}: {defn}"

    if scenario:
        return f"When the stem mentions \"{scenario}\", think {label_l} first."

    return f"Before you pick, say aloud what the question is really asking, then match {label_l}."


def resolve_practice_hint(item: dict[str, Any]) -> str:
    """Use stored hint unless it is generic or Messer PDF boilerplate."""
    stored = (item.get("hint") or "").strip()
    if stored and stored != GENERIC_HINT:
        low = stored.lower()
        if "professormesser.link" not in low and "practice exam" not in low:
            return stored

    correct_explain = (item.get("correct_explain") or "").strip()
    if not correct_explain:
        prov = item.get("provenance") or item.get("provenance_json")
        if isinstance(prov, str):
            try:
                prov = json.loads(prov)
            except json.JSONDecodeError:
                prov = {}
        if isinstance(prov, dict):
            correct_explain = (prov.get("correct_explain") or "").strip()

    return build_practice_hint(
        prompt=item.get("prompt") or item.get("stem") or item.get("q") or "",
        choices=item.get("choices") or [],
        answer_idx=int(item.get("answer_idx", 0)),
        correct_explain=correct_explain,
        more_info=_more_info_from_item(item),
    )
