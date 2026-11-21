"""One-shot: complete truncated Sec+ MCQ choice fragments in secplus_lessons.py."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "secplus_lessons.py"

REPS: list[tuple[str, str]] = [
    (
        "Gap / untreated risk until mitigated or",
        "Gap / untreated risk until mitigated or formally accepted",
    ),
    (
        "Fraud staging: warn finance, treat as part of",
        "Fraud staging: warn finance and treat as part of BEC",
    ),
    (
        "Hunt both cloud SigninLogs and on-prem 462x as",
        "Hunt both cloud SigninLogs and on-prem 462x events",
    ),
    (
        "You need control after the file leaves the",
        "You need control after the file leaves the org",
    ),
    (
        "You have a resilience gap to fix or",
        "You have a resilience gap to fix or renegotiate",
    ),
    (
        "So SOC can treat matching traffic as",
        "So SOC can treat matching traffic as expected",
    ),
    (
        "Coordinating multiple tools/actions in a",
        "Coordinating tools and actions in one playbook",
    ),
    (
        "Clear who is Responsible/Accountable for",
        "Clear who is Responsible/Accountable for each task",
    ),
    (
        "Unacceptable: hide findings destroys trust and",
        "Unacceptable: hiding findings destroys trust and audit value",
    ),
    (
        "HR-specific phishing/macro briefing AND",
        "HR-specific phishing/macro briefing AND contain the path",
    ),
    (
        "Incidents change controls, training, and",
        "Incidents change controls, training, and process",
    ),
    (
        "A preventive network control is missing or",
        "A missing preventive network control",
    ),
    (
        "So you can say 'detective technical' without",
        "So you can say 'detective technical' without mixing axes",
    ),
    (
        "dcount of users (or count by src_ip) in a",
        "dcount of users per src_ip per window",
    ),
    (
        "Pick the control that closes the",
        "Pick the control that closes the actual risk",
    ),
    (
        "Endpoint DLP blocking paste/upload of",
        "Endpoint DLP blocking paste/upload of sensitive data",
    ),
    (
        "Keep critical business functions through",
        "Keep critical business functions through disruption",
    ),
    (
        "Verify with scan/firewall config + monitor for",
        "Verify with scan/firewall config and monitor for reopens",
    ),
    (
        "Restoring service securely and monitoring for",
        "Restoring service securely and monitoring for relapse",
    ),
    (
        "Who handled evidence when",
        "Who handled evidence when, and with what hashes",
    ),
    (
        "Pasted into ticket with",
        "In the ticket with timestamps + hashes",
    ),
    (
        "Say/do gap: written intent not enforced (or",
        "Say/do gap: policy not enforced in config",
    ),
    (
        "How much risk leadership allows in pursuit of",
        "Risk leadership accepts to pursue objectives",
    ),
    (
        "Scope, timing, contacts, data handling, and",
        "Scope, timing, contacts, and stop rules",
    ),
    (
        "Easy, non-punitive reporting of",
        "Easy, non-punitive reporting of suspected incidents",
    ),
    (
        "Authorization deciding what the identity may",
        "Authorization deciding what the identity may do",
    ),
    (
        "A resilience and security failure waiting to",
        "A resilience and security failure waiting to happen",
    ),
]


def main() -> None:
    """Replace each truncated choice only where it is a whole quoted string literal."""
    text = PATH.read_text(encoding="utf-8")
    missing: list[str] = []
    for old, new in REPS:
        hits = 0
        for quote in ("'", '"'):
            needle = f"{quote}{old}{quote}"
            hits += text.count(needle)
            text = text.replace(needle, f"{quote}{new}{quote}")
        if not hits:
            missing.append(old)
    if missing:
        print(f"MISSING {len(missing)}")
        for m in missing:
            print(" ", m)
        raise SystemExit(1)
    PATH.write_text(text, encoding="utf-8")
    print(f"OK replaced {len(REPS)} fragments in {PATH.name}")


if __name__ == "__main__":
    main()
