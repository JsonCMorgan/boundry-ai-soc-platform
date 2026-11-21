"""Shared Sec+ MCQ length-bias and incomplete-choice helpers (audit / tests)."""
from __future__ import annotations

import re

PCT_THRESH = 20.0
ABS_THRESH = 15

# High-precision: almost always a truncated mid-thought (lint / tests).
_DANGLING_END = re.compile(
    r"(?i)\b("
    r"if|to|and|or|the|a|an|of|for|with|by|from|than|as|via|"
    r"when|while|into|onto|through|without|because|until|versus|vs|"
    r"may|might|shall"
    r")\s*$"
)

# Broader closed-class endings used only when shortening rewrite output.
_SHORTEN_UNSAFE_END = re.compile(
    r"(?i)\b("
    r"if|to|and|or|the|a|an|of|for|with|by|from|than|as|via|"
    r"when|while|into|onto|through|without|because|until|versus|vs|"
    r"is|are|was|were|be|been|being|has|have|had|"
    r"will|would|should|could|can|may|might|must|shall|"
    r"do|does|did|not|only"
    r")\s*$"
)

# Legitimate short exam labels (not truncated sentences).
_SHORT_OK = frozenset(
    {
        "physical",
        "managerial",
        "technical",
        "operational",
        "detective",
        "preventive",
        "corrective",
        "directive",
        "compensating",
        "rto",
        "rpo",
        "bcp",
        "dr",
        "mfa",
        "cia",
        "aaa",
        "iam",
        "sso",
        "vpn",
        "vlan",
        "ids",
        "ips",
        "siem",
        "soar",
        "edr",
        "dlp",
        "pki",
        "tls",
        "ssh",
        "rdp",
        "smb",
        "dns",
        "http",
        "https",
        "ftp",
        "otp",
        "pin",
        "pam",
        "nac",
        "waf",
        "ngfw",
        "casb",
        "ztna",
        "ueba",
        "xdr",
        "ndr",
        "iot",
        "ot",
        "scada",
        "ics",
        "saas",
        "iaas",
        "paas",
        "chg success",
        "rto math",
    }
)


def choice_lengths(choices: list[str]) -> list[int]:
    """Character lengths for each choice."""
    return [len(str(c)) for c in choices]


def incomplete_choice_reasons(text: str) -> list[str]:
    """
    Return reason codes if a choice looks truncated / incomplete.

    Empty list means the choice passes incomplete-choice checks.
    Short allowlisted exam labels (e.g. Physical, RTO) are not flagged.
    """
    s = " ".join(str(text or "").split()).strip()
    if not s:
        return ["empty"]
    key = s.lower().rstrip(".")
    if key in _SHORT_OK:
        return []
    reasons: list[str] = []
    if s.endswith(("...", "…")):
        reasons.append("ellipsis")
    if s.endswith(("(", "/", "-")):
        reasons.append("open_cut")
    if _DANGLING_END.search(s):
        reasons.append("dangling")
    return reasons


def is_incomplete_choice(text: str) -> bool:
    """True when choice text fails incomplete-choice checks."""
    return bool(incomplete_choice_reasons(text))


def is_shorten_unsafe(text: str) -> bool:
    """
    True when shortened rewrite text looks cut mid-thought.

    Broader than is_incomplete_choice so shorten() never ships
    endings like '... identity is'.
    """
    s = " ".join(str(text or "").split()).strip()
    if not s:
        return True
    key = s.lower().rstrip(".")
    if key in _SHORT_OK:
        return False
    if s.endswith(("...", "…", "(", "/", "-")):
        return True
    return bool(_SHORTEN_UNSAFE_END.search(s))


def is_correct_longest(choices: list[str], answer_idx: int) -> bool:
    """True when the correct choice is strictly longest by characters."""
    lens = choice_lengths(choices)
    idx = int(answer_idx)
    return lens[idx] > max(lens[i] for i in range(len(lens)) if i != idx)


def is_severe_length_bias(choices: list[str], answer_idx: int) -> bool:
    """Correct is longest AND (>=20% longer than next OR >=15 chars longer)."""
    if len(choices) != 4:
        return False
    lens = choice_lengths(choices)
    idx = int(answer_idx)
    corr = lens[idx]
    max_other = max(lens[i] for i in range(4) if i != idx)
    if corr <= max_other:
        return False
    pct = (corr - max_other) / max_other * 100 if max_other else 100.0
    abs_over = corr - max_other
    return pct >= PCT_THRESH or abs_over >= ABS_THRESH


def lint_mcq_banks(
    practice: dict,
    quizzes: dict,
    *,
    hard_fail: bool = True,
) -> list[str]:
    """
    Lint practice+quiz 4-choice MCQs for severe correct-longest bias.

    Returns list of offender messages. Raises AssertionError when hard_fail
    and any severe offenders exist.
    """
    offenders: list[str] = []
    banks = (("practice", practice, "prompt"), ("quiz", quizzes, "q"))
    total = 0
    severe_n = 0
    longest_n = 0
    for bank_name, bank, stem_key in banks:
        for lesson_id, items in bank.items():
            for item in items:
                choices = item.get("choices") or []
                if len(choices) != 4:
                    continue
                total += 1
                idx = int(item["answer_idx"])
                if not (0 <= idx < 4):
                    offenders.append(
                        f"{bank_name}:{item.get('id', lesson_id)} answer_idx={idx} out of range"
                    )
                    continue
                if is_correct_longest(choices, idx):
                    longest_n += 1
                if is_severe_length_bias(choices, idx):
                    severe_n += 1
                    lens = choice_lengths(choices)
                    corr = lens[idx]
                    max_other = max(lens[i] for i in range(4) if i != idx)
                    stem = (item.get(stem_key) or item.get("prompt") or item.get("q") or "")[:70]
                    offenders.append(
                        f"{bank_name}:{item.get('id', '?')} lens={lens} "
                        f"correct={corr} next={max_other} stem={stem!r}"
                    )
    summary = (
        f"MCQ length lint: total={total} longest={longest_n} "
        f"({(100 * longest_n / total) if total else 0:.1f}%) "
        f"severe={severe_n} ({(100 * severe_n / total) if total else 0:.1f}%)"
    )
    print(summary)
    if hard_fail and offenders:
        preview = "\n".join(offenders[:12])
        raise AssertionError(
            f"Severe MCQ length bias in {len(offenders)} item(s).\n{preview}"
        )
    return offenders


def lint_mcq_incomplete(
    practice: dict,
    quizzes: dict,
    *,
    hard_fail: bool = True,
) -> list[str]:
    """
    Lint practice+quiz 4-choice MCQs for truncated / incomplete choice text.

    Returns offender messages. Raises AssertionError when hard_fail and any exist.
    """
    offenders: list[str] = []
    banks = (("practice", practice, "prompt"), ("quiz", quizzes, "q"))
    total = 0
    for bank_name, bank, stem_key in banks:
        for lesson_id, items in bank.items():
            for item in items:
                choices = item.get("choices") or []
                if len(choices) != 4:
                    continue
                total += 1
                qid = item.get("id", lesson_id)
                for i, choice in enumerate(choices):
                    reasons = incomplete_choice_reasons(choice)
                    if not reasons:
                        continue
                    stem = (
                        item.get(stem_key)
                        or item.get("prompt")
                        or item.get("q")
                        or ""
                    )[:70]
                    offenders.append(
                        f"{bank_name}:{qid} [{i}] {','.join(reasons)} "
                        f"choice={str(choice)!r} stem={stem!r}"
                    )
    summary = (
        f"MCQ incomplete lint: total={total} incomplete={len(offenders)}"
    )
    print(summary)
    if hard_fail and offenders:
        preview = "\n".join(offenders[:20])
        raise AssertionError(
            f"Incomplete MCQ choices in {len(offenders)} place(s).\n{preview}"
        )
    return offenders
