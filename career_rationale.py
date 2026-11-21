"""
Helpers for Career prove-it answer chips (hover rationale popouts).
"""

from __future__ import annotations

from typing import Any


def chip(
    *,
    id: str,
    label: str,
    matched: bool,
    rationale: str,
    title: str | None = None,
    row_label: str | None = None,
) -> dict[str, Any]:
    """One hoverable correct-answer chip for BoundryRationale.renderResult."""
    return {
        "id": id,
        "label": label,
        "matched": bool(matched),
        "rationale": (rationale or "").strip(),
        "title": title or "Why this answer",
        "row_label": row_label or title or "Correct answer",
    }


def disposition_chip(
    *,
    correct_id: str,
    label: str,
    matched: bool,
    teach: str,
    why: str = "",
) -> dict[str, Any]:
    """Standard disposition answer chip."""
    rationale = " ".join(
        p for p in (
            f"Why this disposition: {why}" if why else "",
            f"For this case: {teach}" if teach else "",
        )
        if p
    ).strip() or teach
    return chip(
        id="disposition",
        label=label or correct_id,
        matched=matched,
        rationale=rationale,
        title="Why this disposition",
        row_label="Correct disposition",
    )
