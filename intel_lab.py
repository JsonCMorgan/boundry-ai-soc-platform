"""
G6 — Local IOC enrichment / threat intel lookup bench.

Option A (hire-aligned, simplest): stub reputation for IP / domain / hash,
then force a short ticket note. No live VirusTotal/Shodan (privacy + offline).
Original Boundry IOCs only (documentation ranges / fake hashes).
"""

from __future__ import annotations

import re
from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "IOC Enrichment Lab"
TRACK_BLURB = (
    "Practice the enrich-before-escalate habit. Look up an indicator of compromise "
    "(IOC): an IP, domain, or file hash. Read a local reputation stub, then write "
    "a ticket-ready note. Nothing leaves this machine."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "IOC",
        "plain": "Indicator of Compromise: a clue you can search for (bad IP, phishing domain, malware file hash).",
    },
    {
        "term": "Enrichment",
        "plain": "Looking up context on an IOC before you escalate or close (reputation, geography, first-seen, related alerts).",
    },
    {
        "term": "Reputation stub",
        "plain": "A local practice database that simulates vendor intel. Boundry does not call cloud threat intel APIs here.",
    },
    {
        "term": "Ticket note",
        "plain": "Short evidence write-up: what you looked up, what it said, and what you recommend next.",
    },
]

# Local reputation table (offline stub). Keys normalized lowercase.
REPUTATION: dict[str, dict[str, Any]] = {
    "203.0.113.88": {
        "ioc_type": "ip",
        "verdict": "malicious",
        "score": 92,
        "tags": ["c2", "malware_hosting"],
        "geo": "Documentation range (TEST-NET-3)",
        "summary": "Known in Boundry stub as a download/C2 host used in EDR lab samples.",
        "first_seen": "2026-08-12",
    },
    "198.51.100.77": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 68,
        "tags": ["scanner", "rare_port"],
        "geo": "Documentation range (TEST-NET-2)",
        "summary": "Seen in stub as destination for odd egress (port 4444). Not confirmed malware alone.",
        "first_seen": "2026-09-01",
    },
    "8.8.8.8": {
        "ioc_type": "ip",
        "verdict": "benign",
        "score": 5,
        "tags": ["public_dns"],
        "geo": "Public DNS",
        "summary": "Well-known public DNS resolver. Not a reason to escalate by itself.",
        "first_seen": "n/a",
    },
    "192.0.2.55": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 72,
        "tags": ["test_net", "sql_injection_sim"],
        "geo": "Documentation range (TEST-NET-1)",
        "summary": "Boundry stub: seen in simulated web SQL injection alerts (administrator user). Validate in app logs; block only per policy.",
        "first_seen": "2026-10-01",
    },
    "c0ntoso-finance.com": {
        "ioc_type": "domain",
        "verdict": "malicious",
        "score": 88,
        "tags": ["lookalike", "phishing"],
        "geo": "n/a",
        "summary": "Lookalike of contoso.com used in Boundry BEC / proxy drills. Treat as phishing infrastructure.",
        "first_seen": "2026-09-20",
    },
    "login.microsoftonline.com": {
        "ioc_type": "domain",
        "verdict": "benign",
        "score": 2,
        "tags": ["microsoft", "auth"],
        "geo": "n/a",
        "summary": "Legitimate Microsoft sign-in host. Do not block as phishing without other evidence.",
        "first_seen": "n/a",
    },
    "a3f5c8e1b2d9470f6e4a1c9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e": {
        "ioc_type": "hash",
        "verdict": "malicious",
        "score": 95,
        "tags": ["trojan", "powershell_dropper"],
        "geo": "n/a",
        "summary": "Stub SHA-256 for a Boundry practice dropper. Escalate and preserve the sample path.",
        "first_seen": "2026-07-04",
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "ioc_type": "hash",
        "verdict": "benign",
        "score": 0,
        "tags": ["empty_file"],
        "geo": "n/a",
        "summary": "SHA-256 of empty file. Benign hash; check why it appeared in the alert.",
        "first_seen": "n/a",
    },
    "micr0soft-secure.com": {
        "ioc_type": "domain",
        "verdict": "malicious",
        "score": 90,
        "tags": ["credential_harvest", "lookalike"],
        "geo": "n/a",
        "summary": "Lookalike Microsoft login host used in Boundry credential-harvest drills.",
        "first_seen": "2026-10-01",
    },
    "198.51.100.200": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 55,
        "tags": ["vpn_exit", "shared"],
        "geo": "Documentation range (TEST-NET-2)",
        "summary": "Shared VPN exit stub. Suspicious only with other signals; not enough alone to declare malware.",
        "first_seen": "2026-09-15",
    },
    "update.microsoft.com": {
        "ioc_type": "domain",
        "verdict": "benign",
        "score": 1,
        "tags": ["microsoft", "patch"],
        "geo": "n/a",
        "summary": "Legitimate Microsoft update host. Do not escalate solely because a host contacted it.",
        "first_seen": "n/a",
    },
}


def _case(
    cid: str,
    title: str,
    difficulty: int,
    ioc: str,
    scenario: str,
    teach: str,
    disposition: str,
    checklist: dict[str, bool],
    note_must_include: list[str],
) -> dict[str, Any]:
    return {
        "id": cid,
        "title": title,
        "difficulty": difficulty,
        "ioc": ioc,
        "scenario": scenario.strip(),
        "teach": teach,
        "correct_disposition": disposition,
        "checklist_answers": checklist,
        "note_must_include": note_must_include,
    }


CASES: list[dict[str, Any]] = [
    _case(
        "c2_ip_download",
        "Workstation pulled from 203.0.113.88",
        1,
        "203.0.113.88",
        """
EDR alert: curl.exe downloaded u.exe from http://203.0.113.88/u.exe on WS-HR-03.
Your job: enrich the IP, then pick disposition and write a ticket note.
""",
        "Malicious stub reputation + download context means escalate with the IOC and host in the note.",
        "escalate_with_ioc",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": True,
            "benign_public_service": False,
            "note_has_verdict": True,
        },
        ["203.0.113.88", "malicious", "escalate"],
    ),
    _case(
        "dns_benign",
        "Alert mentions 8.8.8.8",
        1,
        "8.8.8.8",
        """
SIEM noisy alert: host WS-IT-02 sent DNS queries to 8.8.8.8.
Some orgs block public DNS; others allow it. Enrich before you panic.
""",
        "Public DNS is usually benign. Document the lookup. Escalate only if policy forbids it or other IOCs exist.",
        "close_or_policy_note",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": False,
            "benign_public_service": True,
            "note_has_verdict": True,
        },
        ["8.8.8.8", "benign"],
    ),
    _case(
        "lookalike_domain",
        "Proxy allow to c0ntoso-finance.com",
        2,
        "c0ntoso-finance.com",
        """
Proxy log: ap.clerk clicked https://c0ntoso-finance.com/wire-approve (HTTP 200).
Email team already flagged a lookalike CFO wire message.
""",
        "Lookalike domain with malicious stub score supports phishing / BEC escalation, especially with a click.",
        "escalate_with_ioc",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": True,
            "benign_public_service": False,
            "note_has_verdict": True,
        },
        ["c0ntoso-finance.com", "malicious", "phish"],
    ),
    _case(
        "hash_dropper",
        "Hash match on downloaded file",
        2,
        "a3f5c8e1b2d9470f6e4a1c9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e",
        """
EDR reported file hash after the curl download on WS-HR-03.
Enrich the SHA-256 before you ask IR to take the host.
""",
        "Malicious hash stubs justify isolate/escalate language and preserving the path.",
        "escalate_with_ioc",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": True,
            "benign_public_service": False,
            "note_has_verdict": True,
        },
        ["malicious", "hash", "escalate"],
    ),
    _case(
        "ms_lookalike_login",
        "User reported micr0soft-secure.com",
        1,
        "micr0soft-secure.com",
        """
Help desk: user got a password-reset email and almost opened the link.
Enrich the domain before you write the ticket note.
""",
        "Malicious lookalike login domain means escalate with the IOC. Coach the user not to enter credentials.",
        "escalate_with_ioc",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": True,
            "benign_public_service": False,
            "note_has_verdict": True,
        },
        ["micr0soft-secure.com", "malicious", "phish"],
    ),
    _case(
        "vpn_exit_shared",
        "Alert on shared VPN exit 198.51.100.200",
        2,
        "198.51.100.200",
        """
SIEM: one successful sign-in from 198.51.100.200 for a traveling exec.
Enrich before you call it C2.
""",
        "Shared VPN exits are often suspicious-not-malicious. Document the stub verdict; escalate only with more host or identity evidence.",
        "close_or_policy_note",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": True,
            "benign_public_service": False,
            "note_has_verdict": True,
        },
        ["198.51.100.200", "suspicious"],
    ),
    _case(
        "ms_update_benign",
        "Host contacted update.microsoft.com",
        1,
        "update.microsoft.com",
        """
EDR noisy alert: WS-OPS-02 connected to update.microsoft.com during patch window.
Enrich before you open an IR bridge.
""",
        "Microsoft update domains are benign. Close with a policy note unless the process tree looks hostile.",
        "close_or_policy_note",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": False,
            "benign_public_service": True,
            "note_has_verdict": True,
        },
        ["update.microsoft.com", "benign"],
    ),
    _case(
        "empty_hash_noise",
        "Empty-file hash in alert payload",
        2,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        """
Parser bug dropped an empty file hash into an alert about a failed download.
Enrich the hash before you escalate malware.
""",
        "Empty-file hash is benign. Fix the note quality; do not escalate malware on this hash alone.",
        "close_or_policy_note",
        {
            "looked_up_ioc": True,
            "malicious_or_suspicious": False,
            "benign_public_service": True,
            "note_has_verdict": True,
        },
        ["benign", "empty"],
    ),
]

DISPOSITIONS = [
    {
        "id": "escalate_with_ioc",
        "label": "Escalate with IOC + host/user evidence",
        "why": "Reputation is malicious/suspicious and activity supports compromise or phishing.",
    },
    {
        "id": "close_or_policy_note",
        "label": "Close / policy note (benign or expected)",
        "why": "Reputation is benign public service or empty-file noise; document and move on unless policy says otherwise.",
    },
    {
        "id": "block_without_note",
        "label": "Block IOC globally with no ticket note",
        "why": "Wrong for L1 training: always leave a note so the next analyst knows why.",
    },
    {
        "id": "ignore_no_lookup",
        "label": "Ignore alert without enrichment",
        "why": "Wrong: enrichment is the point of this lab.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "looked_up_ioc",
        "label": "I ran the local reputation lookup on the IOC in this case",
    },
    {
        "id": "malicious_or_suspicious",
        "label": "Stub verdict is malicious or suspicious (not benign)",
    },
    {
        "id": "benign_public_service",
        "label": "Stub verdict is a known benign public service / empty file",
    },
    {
        "id": "note_has_verdict",
        "label": "My ticket note states the verdict (malicious / suspicious / benign)",
    },
]


def case_ids() -> list[str]:
    """Ordered case ids for next-scenario rotation."""
    return [c["id"] for c in CASES]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards without answer keys (IOC shown; host text varies per open)."""
    return [
        {
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "ioc": c["ioc"],
            "teach": c["teach"],
        }
        for c in CASES
    ]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Return one enrichment case (canonical, no variants)."""
    for c in CASES:
        if c["id"] == case_id:
            return c
    return None


def materialize_case(case_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """
    Variant instance: host/user wording in the scenario.

    IOC and note_must_include stay fixed so local reputation stubs still grade.
    """
    case = get_case(case_id)
    if not case:
        return None
    return career_instances.materialize_generic(
        case,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["scenario", "teach"],
        allow_ip=False,
    )


def next_after(case_id: str) -> dict[str, str]:
    """Random different case + fresh seed under /career/intel."""
    return career_instances.next_scenario(case_ids(), case_id, "/career/intel")


def normalize_ioc(value: str) -> str:
    """Normalize IOC for stub lookup."""
    v = (value or "").strip().lower()
    v = v.removeprefix("http://").removeprefix("https://")
    v = v.split("/")[0]
    return v


def lookup_ioc(value: str) -> dict[str, Any]:
    """
    Local reputation lookup. Never calls the internet.
    Accepts IP, domain, or 64-char hex hash.
    """
    key = normalize_ioc(value)
    if not key:
        return {"ok": False, "error": "Enter an IP, domain, or SHA-256 hash."}
    row = REPUTATION.get(key)
    if not row:
        # Soft unknown — still useful for practice notes
        ioc_type = "unknown"
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", key):
            ioc_type = "ip"
        elif re.fullmatch(r"[a-f0-9]{64}", key):
            ioc_type = "hash"
        elif "." in key:
            ioc_type = "domain"
        return {
            "ok": True,
            "found": False,
            "ioc": key,
            "ioc_type": ioc_type,
            "verdict": "unknown",
            "score": None,
            "tags": [],
            "geo": "n/a",
            "summary": "No stub record. In a real SOC you would try a second source and still document 'unknown'.",
            "first_seen": "n/a",
        }
    return {
        "ok": True,
        "found": True,
        "ioc": key,
        **row,
    }


def _note_hits(note: str, must_include: list[str]) -> tuple[int, list[str]]:
    """Count how many required substrings appear in the note (case-insensitive)."""
    text = (note or "").lower()
    missing = []
    hit = 0
    for token in must_include:
        if token.lower() in text:
            hit += 1
        else:
            missing.append(token)
    return hit, missing


def grade_enrichment(
    case_id: str,
    checklist: dict[str, bool],
    disposition: str,
    note: str,
) -> dict[str, Any]:
    """Grade checklist + disposition + note keywords."""
    case = get_case(case_id)
    if not case:
        return {"ok": False, "error": "Unknown case"}
    answers = case["checklist_answers"]
    items = []
    hit = 0
    for item in CHECKLIST_ITEMS:
        iid = item["id"]
        expected = bool(answers.get(iid))
        got = bool(checklist.get(iid))
        ok = got == expected
        if ok:
            hit += 1
        items.append({
            "id": iid,
            "label": item["label"],
            "expected": expected,
            "got": got,
            "correct": ok,
        })
    disp_ok = (disposition or "").strip() == case["correct_disposition"]
    must = case["note_must_include"]
    note_hit, note_missing = _note_hits(note, must)
    # Need at least ceil(2/3) of keywords, or all if 2 or fewer
    need = max(1, (len(must) + 1) // 2) if len(must) > 2 else len(must)
    note_ok = note_hit >= need and len((note or "").strip()) >= 24
    # Checklist 4 + disposition 2 + note 2
    score = hit + (2 if disp_ok else 0) + (2 if note_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == case["correct_disposition"]), None
    )
    note_chip = career_rationale.chip(
        id="ticket_note",
        label="Ticket note with required IOC facts",
        matched=note_ok,
        rationale=(
            "Your note must name the IOC and what you found so the next analyst "
            f"can act. Required ideas: {', '.join(must)}. For this case: {case['teach']}"
        ),
        title="Why the ticket note matters",
        row_label="Correct note shape",
    )
    _intel_result = {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "disposition_correct": disp_ok,
        "correct_disposition": case["correct_disposition"],
        "note_ok": note_ok,
        "note_missing": note_missing if not note_ok else [],
        "teach": case["teach"],
        "answer_chips": [
            career_rationale.disposition_chip(
                correct_id=case["correct_disposition"],
                label=(disp_meta or {}).get("label") or case["correct_disposition"],
                matched=disp_ok,
                teach=case["teach"],
                why=(disp_meta or {}).get("why") or "",
            ),
            note_chip,
        ],
    }
    # keep trailing keys from original return
    return {**_intel_result,
        "score": score,
        "total": total,
    }
