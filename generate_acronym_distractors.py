"""
One-time (re-runnable) generator for acronym quiz distractors.

For every acronym in security_acronyms.py, asks the local LLM (Ollama) to invent
3 plausible-but-WRONG expansions that mirror the real answer's word structure.
That keeps entries like C2 from becoming obvious because only the correct answer
has the right "Command and Control" shape. Results are cached to
acronym_distractors.json, which the app loads at import time.

Run:   python generate_acronym_distractors.py
Then:  commit acronym_distractors.json so Railway uses it too.

Uses OLLAMA_BASE_URL / OLLAMA_MODEL env vars (defaults: localhost:11434, the
model already used by the app). Skips acronyms that already have cached
distractors unless you pass --all.
"""
import os, re, sys, json, time
import urllib.request
from typing import Any, Dict, List, Optional

import security_acronyms

OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:7b")
CACHE_FILE = os.path.join(os.path.dirname(__file__), "acronym_distractors.json")
REGEN_ALL = "--all" in sys.argv


def _ollama(prompt, timeout=120):
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.8},
    }).encode()
    req = urllib.request.Request(OLLAMA_BASE + "/api/generate", data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()).get("response", "")


JOINERS = {"and", "of", "the", "for", "a", "to", "in", "on", "or"}


def _content_tokens(phrase: str) -> List[Dict[str, Any]]:
    """Return cleaned phrase tokens with joiners marked."""
    tokens = []
    for raw in phrase.split():
        clean = re.sub(r"[^A-Za-z]", "", raw)
        if clean:
            tokens.append({"clean": clean, "joiner": clean.lower() in JOINERS})
    return tokens


def _shape_ok(phrase: str, full: str) -> bool:
    """Check that a fake mirrors the real answer's word count and initials."""
    fake_tokens = _content_tokens(phrase)
    real_tokens = _content_tokens(full)
    if len(fake_tokens) != len(real_tokens):
        return False
    for fake, real in zip(fake_tokens, real_tokens):
        if fake["joiner"] != real["joiner"]:
            return False
        if real["joiner"] and fake["clean"].lower() != real["clean"].lower():
            return False
        if not real["joiner"] and fake["clean"][0].upper() != real["clean"][0].upper():
            return False
    return phrase.strip().lower() != full.strip().lower()


def gen_for(abbr: str, full: str, definition: str) -> Optional[List[str]]:
    real_tokens = _content_tokens(full)
    shape = " ".join(
        token["clean"].lower() if token["joiner"] else token["clean"][0].upper() + "..."
        for token in real_tokens
    )
    prompt = (
        f"You write distractor answers for a cybersecurity acronym quiz.\n"
        f"Acronym: {abbr}\nReal meaning: {full}\n"
        f"Definition: {definition}\n"
        f"Required answer shape: {shape}\n"
        f"Invent exactly 3 FAKE expansions of '{abbr}' that:\n"
        f"- are NOT the real meaning\n"
        f"- have the same number of words as the real meaning\n"
        f"- keep connector words in the exact same positions, such as and/of/the\n"
        f"- make every non-connector word start with the same letter as the real meaning's word in that position\n"
        f"- sound like plausible real security/IT terms\n"
        f"Return ONLY a JSON array of 3 strings, nothing else."
    )
    for _ in range(3):
        try:
            raw = _ollama(prompt)
            m = re.search(r"\[.*\]", raw, re.DOTALL)
            if not m:
                continue
            arr = json.loads(m.group())
            out = []
            for s in arr:
                s = str(s).strip()
                if s and s.lower() != full.lower() and s not in out and _shape_ok(s, full):
                    out.append(s)
            if len(out) >= 3:
                return out[:3]
        except Exception as exc:
            print(f"   retry ({exc})")
            time.sleep(1)
    return None


def main():
    cache = {}
    if os.path.exists(CACHE_FILE):
        cache = json.load(open(CACHE_FILE, encoding="utf-8"))
    done = skipped = failed = 0
    for e in security_acronyms.ACRONYMS:
        abbr = e["abbr"]
        cached = cache.get(abbr, [])
        if not REGEN_ALL and len(cached) == 3 and all(_shape_ok(str(s), e["full"]) for s in cached):
            skipped += 1
            continue
        print(f"Generating {abbr} …")
        res = gen_for(abbr, e["full"], e["def"])
        if res:
            cache[abbr] = res
            done += 1
        else:
            failed += 1
            print(f"   FAILED {abbr} — will fall back at quiz time")
        json.dump(cache, open(CACHE_FILE, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\nDone. generated={done} skipped={skipped} failed={failed} -> {CACHE_FILE}")


if __name__ == "__main__":
    main()
