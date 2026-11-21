"""One-shot: rebalance severe correct-longest MCQs via runtime banks, then patch file."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from secplus_lessons import PRACTICE, QUIZZES  # noqa: E402
from secplus_mcq_length_lint import (  # noqa: E402
    is_incomplete_choice,
    is_severe_length_bias,
)

PATH = ROOT / "secplus_lessons.py"

# Explicit rewrites for known severe items (complete, length-balanced).
REWRITES: dict[str, list[str]] = {
    "sp_d2_03_vectors_remote_supply_p5": [
        "Only CVE misconfiguration on the DC host",
        "Messaging CAPTCHA-abuse identity path",
        "Removable media at reception desk only",
        "Directive change ticket without enforce",
    ],
    "sp_d2_04_vulns_misconfig_p5": [
        "Safe because the commit is years old",
        "Only a physical cage lock failure case",
        "Stale credential left in a public repo",
        "Proof that DLP already blocked everything",
    ],
    "sp_d2_12_ai_usage_threats_p4": [
        "Font theme misconfiguration as the only issue",
        "Agent tool abuse after a hostile prompt",
        "Mandatory public S3 for all chat logs",
        "Proof CVSS rose on the VPN appliance",
    ],
    "sp_d3_08_backup_rto_p1": [
        "Restores must be tested and backup identity protected",
        "Veeam always needs internet RDP open to restore",
        "Resilience is only about physical site distance",
        "Never isolate a host if any backup job exists",
    ],
    "sp_d3_08_backup_rto_p3": [
        "Printer toner shortages as the main concern",
        "Ransomware deleting or encrypting backups",
        "Phishing posters in the lobby as the fix",
        "Legacy authentication alone as the answer",
    ],
    "sp_d4_10_automation_soar_p3": [
        "Assuming one tool alone closes the whole gap",
        "Coordinating tools and actions via a playbook",
        "Only awareness posters in the break room forever",
        "Only physical locks with no cyber detection at all",
    ],
    "q_d1_01c": [
        "The preventive control is clearly working",
        "Only a deterrent control failed here",
        "Confidentiality is automatically still fine here",
        "A preventive network control is missing",
    ],
    "q_d2_06e": [
        "Assume a VPN connect equals full trust always",
        "Count distinct users by source IP in a window",
        "Delete all 4625 rows before you hunt",
        "Ignore the source IP field forever after",
    ],
    "q_d3_08a": [
        "Max downtime allowed to restore service",
        "Password length rules as the RTO metric",
        "How many VLANs the site currently has",
        "Data classification labels as the only metric",
    ],
    "q_d3_08b": [
        "Never test if backup job icons stay green",
        "On a defined cadence, not disaster day only",
        "Only when RDP is open from the internet",
        "Only after firing the on-call analyst team",
    ],
    "q_d3_08c": [
        "Speed up password spray testing for attackers",
        "Survive ransomware hitting online backups",
        "Disable EDR agents during every restore window",
        "Skip MFA for backup admins as a shortcut",
    ],
    "q_d3_08d": [
        "A hardened recovery best practice by default",
        "A resilience failure waiting to happen",
        "Required by every zero trust design always",
        "A honeypot used instead of real monitoring",
    ],
    "q_d3_08e": [
        "RPO is already fully met tonight",
        "Backup frequency fails the RPO target",
        "RTO becomes automatically zero here",
        "HA clustering alone fixes the RPO gap",
    ],
    "q_d4_13d": [
        "Kept only in your head after the call",
        "Deleted from the ticket after five minutes",
        "Pasted into the ticket with hashes",
        "Call every alert a corrective control forever",
    ],
    "q_d5_01e": [
        "Governance success because a PDF got signed",
        "Automatic transfer of all risk to the ISP",
        "Proof that awareness posters alone are enough",
        "Say/do gap: policy text not enforced live",
    ],
    "q_d5_04c": [
        "Using only CVE count as the primary risk answer",
        "Call every alert a corrective control forever",
        "Choosing only RDP instead of the right control",
        "How much risk leadership allows for objectives",
    ],
    "q_d5_08e": [
        "Only the scanner logo color on the report",
        "Permission to attack any system at any time",
        "Scope, timing, contacts, and data handling rules",
        "A promise that findings need no named owners",
    ],
}


def _py_str(s: str) -> str:
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _replace_choices_block(text: str, old_choices: list[str], new_choices: list[str]) -> str:
    """Replace a 4-choice list even when strings are adjacent-concatenated."""
    # Build a flexible pattern for the old choices as they may appear split.
    parts = []
    for c in old_choices:
        words = re.escape(c).split(r"\ ")
        # Allow optional closing/opening quotes + whitespace between words
        flex = r"(?:'\s*')?".join(words)
        parts.append(flex)
    # Match choices list contents roughly
    pat = (
        r"\["
        + r"\s*,\s*".join(rf"'{p}'" for p in parts)
        + r"\]"
    )
    # Simpler path: replace each old choice string occurrence once if unique enough
    out = text
    for old, new in zip(old_choices, new_choices):
        if old == new:
            continue
        # Handle split adjacent strings: 'foo ' 'bar'
        if old not in out:
            # try split at last space groups of ~40 chars
            mid = len(old) // 2
            # find a space near mid
            sp = old.rfind(" ", 0, mid + 10)
            if sp == -1:
                sp = old.find(" ", mid)
            if sp != -1:
                a, b = old[: sp + 1], old[sp + 1 :]
                split_form = f"'{a}'\n                                      '{b}'"
                split_form2 = f"'{a}' '{b}'"
                joined = f"'{new}'"
                if split_form in out:
                    out = out.replace(split_form, joined, 1)
                    continue
                if split_form2 in out:
                    out = out.replace(split_form2, joined, 1)
                    continue
            raise ValueError(f"Could not find choice in file: {old!r}")
        out = out.replace(f"'{old}'", f"'{new}'", 1)
    return out


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    banks = {**{i["id"]: i for items in PRACTICE.values() for i in items if "id" in i},
             **{i["id"]: i for items in QUIZZES.values() for i in items if "id" in i}}

    for qid, new_choices in REWRITES.items():
        item = banks.get(qid)
        if not item:
            raise SystemExit(f"Unknown id {qid}")
        old = [str(c) for c in item["choices"]]
        idx = int(item["answer_idx"])
        if len(new_choices) != 4:
            raise SystemExit(f"{qid}: need 4 choices")
        for c in new_choices:
            if is_incomplete_choice(c):
                raise SystemExit(f"{qid}: incomplete new choice {c!r}")
        if is_severe_length_bias(new_choices, idx):
            lens = [len(c) for c in new_choices]
            raise SystemExit(f"{qid}: still severe after rewrite lens={lens}")
        text = _replace_choices_block(text, old, new_choices)
        print(f"OK {qid}")

    PATH.write_text(text, encoding="utf-8")
    print(f"Wrote {PATH.name}")


if __name__ == "__main__":
    main()
