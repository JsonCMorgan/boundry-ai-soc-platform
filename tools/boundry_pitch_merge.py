"""Merge golden pitch items with Ollama-generated JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GEN_PATH = ROOT / "data" / "boundry_pitch" / "generated_items.json"


def norm_stem(item: dict[str, Any]) -> str:
    if item.get("type") == "flash":
        return (item.get("term") or "").strip().lower()
    return (item.get("q") or "").strip().lower()


def load_generated_by_deck() -> dict[str, list[dict[str, Any]]]:
    if not GEN_PATH.is_file():
        return {}
    data = json.loads(GEN_PATH.read_text(encoding="utf-8"))
    return data.get("decks") or {}


def merge_decks(golden: dict[str, Any]) -> dict[str, Any]:
    """Return deck document with golden items first, then generated, deduped."""
    gen = load_generated_by_deck()
    decks_out: list[dict[str, Any]] = []
    for deck in golden.get("decks") or []:
        did = deck["id"]
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        for src in list(deck.get("items") or []) + list(gen.get(did, [])):
            key = norm_stem(src)
            if not key or key in seen:
                continue
            seen.add(key)
            items.append(src)
        decks_out.append({**deck, "items": items})
    return {**golden, "decks": decks_out}