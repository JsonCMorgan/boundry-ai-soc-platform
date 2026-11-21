"""Smoke: Sec+ word counts, structure markers, quiz arity, YouTube/stem spam."""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secplus_lessons import LESSONS, QUIZZES, PRACTICE  # noqa: E402


def words(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def body_of(lesson: dict) -> str:
    parts = []
    for sec in lesson.get("sections") or []:
        if isinstance(sec, dict):
            parts.append(str(sec.get("heading") or ""))
            parts.append(str(sec.get("body") or ""))
        elif isinstance(sec, (list, tuple)) and len(sec) >= 2:
            parts.append(str(sec[0]))
            parts.append(str(sec[1]))
    return "\n".join(parts)


MARKERS = [
    "Where you see this at work",
    "In Security+ terms",
    "Technical specifics",
    "Worked example",
    "How to answer on the exam",
    "Common trap",
    "Remember:",
]

SPAM = [
    r"\bYouTube\b",
    r"\bstem\b",
    r"SY0-701 loves",
    r"grab the distractor",
    r"Walk the stem",
]


def main() -> int:
    by: dict[int, list[tuple[str, int]]] = defaultdict(list)
    marker_fails: list[str] = []
    spam_hits: list[str] = []

    for lesson in LESSONS:
        lid = lesson["id"]
        dom = int(lesson["domain_order"])
        text = body_of(lesson)
        by[dom].append((lid, words(text)))
        missing = [m for m in MARKERS if m not in text]
        # D1 gold may use slight variants; require core markers for D2+
        if dom >= 2 and missing:
            marker_fails.append(f"{lid}: missing {missing}")
        for pat in SPAM:
            if re.search(pat, text, flags=re.I):
                # Allow defined "stem" only if previously defined — ban spam phrases
                if pat == r"\bstem\b" and "the question text" in text.lower():
                    continue
                if pat == r"\bstem\b":
                    # flag undefined stem slang
                    if re.search(r"\bstem\b", text) and "question text" not in text.lower():
                        spam_hits.append(f"{lid}: stem slang")
                    continue
                spam_hits.append(f"{lid}: {pat}")

    print("=== Word-count summary ===")
    for dom in sorted(by):
        ws = [w for _, w in by[dom]]
        thin = [lid for lid, w in by[dom] if w < 400]
        print(
            f"D{dom}: n={len(ws)} avg={sum(ws)/len(ws):.0f} "
            f"min={min(ws)} max={max(ws)} under400={len(thin)}"
        )
        if thin:
            print("  still under 400:", ", ".join(thin))

    # Quiz arity (QUIZZES + PRACTICE MC items)
    bad_arity = []
    quiz_n = 0
    items: list[dict] = []
    for bag in (QUIZZES, PRACTICE):
        if isinstance(bag, dict):
            for v in bag.values():
                if isinstance(v, list):
                    items.extend(x for x in v if isinstance(x, dict))
                elif isinstance(v, dict):
                    items.append(v)
        elif isinstance(bag, list):
            items.extend(x for x in bag if isinstance(x, dict))

    for q in items:
        quiz_n += 1
        opts = q.get("options") or q.get("choices") or []
        if len(opts) not in (3, 4, 5):
            bad_arity.append(f"{q.get('id', '?')}: {len(opts)} options")
        ans = q.get("answer")
        if ans is None:
            ans = q.get("correct")
        if isinstance(ans, int) and opts and not (0 <= ans < len(opts)):
            bad_arity.append(f"{q.get('id', '?')}: answer index {ans} out of range")

    print(f"\nQuiz items scanned: {quiz_n}")
    print(f"Marker fails (D2+): {len(marker_fails)}")
    for m in marker_fails[:12]:
        print(" ", m)
    print(f"Spam hits: {len(spam_hits)}")
    for s in spam_hits[:12]:
        print(" ", s)
    print(f"Quiz arity issues: {len(bad_arity)}")
    for b in bad_arity[:12]:
        print(" ", b)

    # Em/en dash pivots in D4/D5 bodies
    dash_hits = []
    for lesson in LESSONS:
        if int(lesson["domain_order"]) not in (4, 5):
            continue
        text = body_of(lesson)
        if "—" in text or "–" in text:
            dash_hits.append(lesson["id"])
    print(f"D4/D5 em/en dash hits: {len(dash_hits)}")
    for d in dash_hits[:10]:
        print(" ", d)

    ok = not marker_fails and not spam_hits and not bad_arity and not dash_hits
    # D4/D5 under 400 hard fail
    d45_thin = [lid for dom in (4, 5) for lid, w in by[dom] if w < 400]
    if d45_thin:
        print("FAIL D4/D5 under 400:", d45_thin)
        ok = False
    print("\nSMOKE:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
