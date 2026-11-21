#!/usr/bin/env python3
"""Generate extra Boundry Pitch Quiz items via local Ollama (batch, offline PWA)."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.boundry_pitch_specs import (  # noqa: E402
    BANNED_TERMS,
    DECK_BRIEFS,
    TARGET_FLASH_PER_DECK,
    TARGET_MCQ_PER_DECK,
)

# Golden deck definitions live in seed script
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "seed_boundry_pitch_pwa", ROOT / "tools" / "seed_boundry_pitch_pwa.py"
)
_seed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_seed)
GOLDEN = _seed.DECK

GEN_PATH = ROOT / "data" / "boundry_pitch" / "generated_items.json"
OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")

SYSTEM = """You write recruiting-interview drill cards for Boundry.AI (offline-first SOC training MSSP lab).
Rules:
- SMB / professional services framing only. No cannabis or dispensary topics.
- Facts must match a private local Flask stack: SIEM, triage, Ollama local AI, pre-revenue lab not 24/7 staffed SOC.
- Junior honest tone. No invented Fortune 500 clients or fake clearances.
- MCQ: exactly 4 choices, one clearly best, answer_idx 0-3, short explain for interview day.
- Flash: term, prompt (say aloud), model answer under 240 chars.
Output ONLY a JSON array, no markdown."""


def _ollama_url() -> str:
    if OLLAMA_BASE.endswith("/v1"):
        return f"{OLLAMA_BASE}/chat/completions"
    return f"{OLLAMA_BASE}/v1/chat/completions"


def call_ollama(user: str, *, temperature: float = 0.45, max_tokens: int = 3072) -> str:
    """Chat completion against local Ollama."""
    payload = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
    ).encode()
    req = urllib.request.Request(
        _ollama_url(), data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _sanitize_json(text: str) -> str:
    """Strip control chars that break json.loads (except newline/tab)."""
    out: list[str] = []
    for ch in text:
        o = ord(ch)
        if ch in "\n\r\t":
            out.append(ch)
        elif o < 32:
            continue
        else:
            out.append(ch)
    return "".join(out)


def _parse_json_array(text: str) -> list[dict[str, Any]]:
    text = _sanitize_json(text.strip())
    fence = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1)
    else:
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            text = text[start : end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        text = re.sub(r",\s*]", "]", text)
        text = re.sub(r",\s*}", "}", text)
        return json.loads(text)


def _norm_stem(item: dict[str, Any]) -> str:
    if item.get("type") == "flash":
        return (item.get("term") or "").strip().lower()
    return (item.get("q") or "").strip().lower()


def _has_banned(item: dict[str, Any]) -> bool:
    blob = json.dumps(item, ensure_ascii=False).lower()
    return any(t in blob for t in BANNED_TERMS)


def validate_item(item: dict[str, Any]) -> str | None:
    """Return error string or None if ok."""
    t = item.get("type")
    if t == "mcq":
        q = (item.get("q") or "").strip()
        if len(q) < 12:
            return "mcq question too short"
        choices = item.get("choices") or []
        if len(choices) != 4 or not all(str(c).strip() for c in choices):
            return "mcq needs 4 non-empty choices"
        try:
            ai = int(item.get("answer_idx", -1))
        except (TypeError, ValueError):
            return "bad answer_idx"
        if ai not in (0, 1, 2, 3):
            return "answer_idx out of range"
        if not (item.get("explain") or "").strip():
            return "missing explain"
    elif t == "flash":
        if not (item.get("term") or "").strip():
            return "flash missing term"
        if not (item.get("prompt") or "").strip():
            return "flash missing prompt"
        if not (item.get("model") or "").strip():
            return "flash missing model"
    else:
        return "unknown type"
    if _has_banned(item):
        return "banned term"
    return None


def count_types(items: list[dict[str, Any]]) -> tuple[int, int]:
    mcq = sum(1 for i in items if i.get("type") == "mcq")
    flash = sum(1 for i in items if i.get("type") == "flash")
    return mcq, flash


def load_generated() -> dict[str, Any]:
    if not GEN_PATH.is_file():
        return {"version": 1, "decks": {}, "generated_at": None, "model": OLLAMA_MODEL}
    return json.loads(GEN_PATH.read_text(encoding="utf-8"))


def save_generated(data: dict[str, Any]) -> None:
    GEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    data["generated_at"] = datetime.now(timezone.utc).isoformat()
    data["model"] = OLLAMA_MODEL
    GEN_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def build_prompt(
    deck_id: str,
    deck_name: str,
    brief: str,
    need_mcq: int,
    need_flash: int,
    existing_stems: list[str],
) -> str:
    avoid = "\n".join(f"- {s[:100]}" for s in existing_stems[:24])
    return (
        f"Deck id={deck_id!r} name={deck_name!r}.\n"
        f"Topic brief: {brief}\n"
        f"Generate exactly {need_mcq} new mcq and {need_flash} new flash items "
        f"(not in the avoid list). Do not duplicate.\n"
        f"Avoid stems:\n{avoid or '(none)'}\n"
        f"Schema per item:\n"
        f'{{"type":"mcq","q":"...","choices":["a","b","c","d"],"answer_idx":1,"explain":"..."}}\n'
        f'{{"type":"flash","term":"...","prompt":"...","model":"..."}}\n'
        f"Return one JSON array of {need_mcq + need_flash} objects."
    )


def generate_for_deck(
    deck: dict[str, Any],
    store: dict[str, list[dict[str, Any]]],
    *,
    dry_run: bool,
    max_rounds: int,
) -> int:
    """Fill generated store for one deck; return count added."""
    did = deck["id"]
    brief = DECK_BRIEFS.get(did, deck["name"])
    golden = list(deck["items"])
    extra = list(store.get(did, []))
    combined = golden + extra
    mcq, flash = count_types(combined)
    added = 0
    rounds = 0
    while (mcq < TARGET_MCQ_PER_DECK or flash < TARGET_FLASH_PER_DECK) and rounds < max_rounds:
        rounds += 1
        need_mcq = max(0, TARGET_MCQ_PER_DECK - mcq)
        need_flash = max(0, TARGET_FLASH_PER_DECK - flash)
        if need_mcq == 0 and need_flash == 0:
            break
        batch_mcq = min(need_mcq, 6)
        batch_flash = min(need_flash, 2)
        stems = [_norm_stem(i) for i in combined if _norm_stem(i)]
        prompt = build_prompt(did, deck["name"], brief, batch_mcq, batch_flash, stems)
        if dry_run:
            print(f"[dry-run] {did}: would request {batch_mcq} mcq + {batch_flash} flash")
            break
        try:
            raw = call_ollama(prompt)
            batch = _parse_json_array(raw)
        except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
            print(f"[warn] {did} round {rounds}: Ollama/parse failed: {exc}")
            continue
        for item in batch:
            err = validate_item(item)
            if err:
                continue
            key = _norm_stem(item)
            if key in stems:
                continue
            extra.append(item)
            combined.append(item)
            stems.append(key)
            added += 1
        mcq, flash = count_types(combined)
        print(f"  {did}: now {mcq} mcq, {flash} flash (target {TARGET_MCQ_PER_DECK}/{TARGET_FLASH_PER_DECK})")
    store[did] = extra
    return added


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Boundry pitch quiz items via Ollama")
    parser.add_argument("--deck", action="append", help="Deck id(s) only (default: all)")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-rounds", type=int, default=12, help="Ollama rounds per deck")
    parser.add_argument("--reset", action="store_true", help="Clear generated items before fill")
    args = parser.parse_args()

    data = load_generated()
    if args.reset:
        data["decks"] = {}
    store: dict[str, list[dict[str, Any]]] = data.get("decks") or {}

    decks = GOLDEN["decks"]
    if args.deck:
        allowed = set(args.deck)
        decks = [d for d in decks if d["id"] in allowed]

    print(f"Ollama {OLLAMA_MODEL} @ {OLLAMA_BASE}")
    total_added = 0
    for deck in decks:
        print(f"=== {deck['id']} ({deck['name']}) ===")
        total_added += generate_for_deck(deck, store, dry_run=args.dry_run, max_rounds=args.max_rounds)

    if not args.dry_run:
        data["decks"] = store
        save_generated(data)
        print(f"Saved {GEN_PATH} (+{total_added} new items)")
        print("Rebuild PWA: python tools/seed_boundry_pitch_pwa.py")


if __name__ == "__main__":
    main()