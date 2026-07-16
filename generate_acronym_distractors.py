"""
One-time (re-runnable) generator for acronym quiz distractors.

For every acronym in security_acronyms.py, asks the local LLM (Ollama) to invent
3 plausible-but-WRONG expansions where each word starts with the acronym's
letters — so quiz options can't be solved by letter-matching. Results are cached
to acronym_distractors.json, which the app loads at import time.

Run:   python generate_acronym_distractors.py
Then:  commit acronym_distractors.json so Railway uses it too.

Uses OLLAMA_BASE_URL / OLLAMA_MODEL env vars (defaults: localhost:11434, the
model already used by the app). Skips acronyms that already have cached
distractors unless you pass --all.
"""
import os, re, sys, json, time
import urllib.request

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


def _letters_ok(phrase, abbr):
    """Best-effort: each word's initial should follow the acronym's letters."""
    letters = [c for c in abbr if c.isalnum()]
    words = re.findall(r"[A-Za-z0-9]+", phrase)
    # allow small joiner words (and, of, the) to be skipped
    words = [w for w in words if w.lower() not in ("and", "of", "the", "for", "a")]
    if len(words) < max(2, len(letters) - 1):
        return False
    initials = "".join(w[0].upper() for w in words)
    target = "".join(letters).upper()
    # loose match: initials should contain the target letters in order
    return target[:3] in initials  # first few letters line up


def gen_for(abbr, full, definition):
    prompt = (
        f"You write distractor answers for a cybersecurity acronym quiz.\n"
        f"Acronym: {abbr}\nReal meaning: {full}\n"
        f"Invent exactly 3 FAKE expansions of '{abbr}' that:\n"
        f"- are NOT the real meaning\n"
        f"- have each word start with the corresponding letter of '{abbr}'\n"
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
                if s and s.lower() != full.lower() and s not in out and _letters_ok(s, abbr):
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
        if not REGEN_ALL and abbr in cache and len(cache[abbr]) == 3:
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
