"""Read-only audit: Sec+ MCQ correct-answer length bias."""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from secplus_lessons import PRACTICE, QUIZZES  # noqa: E402
from secplus_mcq_length_lint import (  # noqa: E402
    ABS_THRESH,
    PCT_THRESH,
    is_correct_longest,
    is_severe_length_bias,
)


def analyze_bank(bank: dict, bank_name: str, stem_key: str) -> list[dict]:
    """Measure correct vs distractor lengths for each 4-choice MCQ."""
    rows: list[dict] = []
    for lesson_id, items in bank.items():
        for item in items:
            choices = item.get("choices") or []
            if len(choices) != 4:
                continue
            idx = int(item["answer_idx"])
            texts = [str(c) for c in choices]
            char_lens = [len(t) for t in texts]
            word_lens = [len(t.split()) for t in texts]
            correct_chars = char_lens[idx]
            correct_words = word_lens[idx]
            other_chars = [char_lens[i] for i in range(4) if i != idx]
            other_words = [word_lens[i] for i in range(4) if i != idx]
            max_other_c = max(other_chars)
            max_other_w = max(other_words)
            is_longest_c = is_correct_longest(texts, idx)
            is_tied_longest_c = correct_chars == max_other_c
            if max_other_c > 0:
                pct_over = (correct_chars - max_other_c) / max_other_c * 100
            else:
                pct_over = 100.0 if correct_chars > 0 else 0.0
            abs_over = correct_chars - max_other_c
            # Dual severe metric: >=20% longer OR >=15 chars longer than next-longest
            severe = is_severe_length_bias(texts, idx)
            assert PCT_THRESH == 20.0 and ABS_THRESH == 15
            stem = item.get(stem_key) or item.get("q") or item.get("prompt") or ""
            rows.append(
                {
                    "bank": bank_name,
                    "id": item.get("id", "?"),
                    "lesson": lesson_id,
                    "stem": stem,
                    "idx": idx,
                    "char_lens": char_lens,
                    "word_lens": word_lens,
                    "correct_chars": correct_chars,
                    "max_other_c": max_other_c,
                    "abs_over": abs_over,
                    "pct_over": pct_over,
                    "is_longest_c": is_longest_c,
                    "is_tied_longest_c": is_tied_longest_c,
                    "is_longest_w": correct_words > max_other_w,
                    "severe": severe,
                    "choices": texts,
                }
            )
    return rows


def stats(rows: list[dict], label: str) -> None:
    """Print aggregate length-bias stats."""
    n = len(rows)
    if n == 0:
        print(f"{label}: 0")
        return
    longest = sum(1 for r in rows if r["is_longest_c"])
    tied = sum(1 for r in rows if r["is_tied_longest_c"])
    longest_or_tied = sum(1 for r in rows if r["is_longest_c"] or r["is_tied_longest_c"])
    longest_w = sum(1 for r in rows if r["is_longest_w"])
    severe = sum(1 for r in rows if r["severe"])
    shortest = sum(
        1
        for r in rows
        if r["correct_chars"]
        < min(r["char_lens"][i] for i in range(4) if i != r["idx"])
    )
    overs = [r["abs_over"] for r in rows if r["is_longest_c"]]
    mean_over = sum(overs) / len(overs) if overs else 0.0
    print(f"=== {label} ===")
    print(f"total_4choice_mcq: {n}")
    print(f"correct_strictly_longest_chars: {longest} ({100 * longest / n:.1f}%)")
    print(f"correct_tied_for_longest_chars: {tied} ({100 * tied / n:.1f}%)")
    print(f"correct_longest_or_tied: {longest_or_tied} ({100 * longest_or_tied / n:.1f}%)")
    print(f"correct_strictly_longest_words: {longest_w} ({100 * longest_w / n:.1f}%)")
    print(
        f"severe (>=20% OR >=15 chars over next): {severe} ({100 * severe / n:.1f}%)"
    )
    print(f"correct_strictly_shortest_chars: {shortest} ({100 * shortest / n:.1f}%)")
    print(f"mean_char_overhang_when_longest: {mean_over:.1f}")
    print()


def count_arity(bank: dict, name: str) -> None:
    """Print choice-count distribution."""
    c: Counter[int] = Counter()
    for items in bank.values():
        for item in items:
            c[len(item.get("choices") or [])] += 1
    print(f"{name} choice-arity: {dict(c)} lessons={len(bank)}")


def main() -> None:
    practice = analyze_bank(PRACTICE, "practice", "prompt")
    quiz = analyze_bank(QUIZZES, "quiz", "q")
    all_rows = practice + quiz

    stats(all_rows, "ALL (practice+quiz)")
    stats(practice, "PRACTICE (Help-me)")
    stats(quiz, "QUIZ (Prove-it)")

    candidates = [r for r in all_rows if r["is_longest_c"]]
    candidates.sort(key=lambda r: (r["pct_over"], r["abs_over"]), reverse=True)
    print("=== WORST 10 (by pct_over among correct-longest) ===")
    for i, r in enumerate(candidates[:10], 1):
        stem = " ".join(r["stem"].split())[:90]
        correct = r["choices"][r["idx"]][:110]
        print(f"{i}. [{r['bank']}] {r['id']}")
        print(
            f"   chars={r['char_lens']} idx={r['idx']} "
            f"correct={r['correct_chars']} next={r['max_other_c']} "
            f"+{r['abs_over']} (+{r['pct_over']:.0f}%) severe={r['severe']}"
        )
        print(f"   words={r['word_lens']}")
        print(f"   stem: {stem}")
        print(f"   correct: {correct}")
        print()

    count_arity(PRACTICE, "PRACTICE")
    count_arity(QUIZZES, "QUIZZES")
    pos_all = Counter(r["idx"] for r in all_rows)
    pos_long = Counter(r["idx"] for r in all_rows if r["is_longest_c"])
    print("answer_idx all:", dict(sorted(pos_all.items())))
    print("answer_idx when longest:", dict(sorted(pos_long.items())))


if __name__ == "__main__":
    main()
