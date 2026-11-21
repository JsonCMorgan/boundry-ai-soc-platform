"""
Automation lite (G18) — safe local enrichment snippets only.

No exploit payloads, no remote attack content. Parse IOCs and format ticket notes.
"""

from __future__ import annotations

import re
from typing import Any

import career_rationale

TRACK_TITLE = "Automation Lite"
TRACK_BLURB = (
    "Short, safe local helpers: pull IOCs out of text and format a ticket note. "
    "This is enrichment glue, not offensive tooling."
)

PRIMER = [
    {
        "term": "IOC",
        "plain": "Indicator of compromise: an IP, domain, or file hash you can look up or block.",
    },
    {
        "term": "Enrichment snippet",
        "plain": "A small script that extracts or formats facts for the ticket. It does not hack anything.",
    },
]

SNIPPETS = {
    "extract_iocs": '''import re

def extract_iocs(text: str) -> dict:
    """Pull IPs, domains, and SHA256-looking hashes from alert text."""
    ips = re.findall(r"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b", text)
    domains = re.findall(r"\\b(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b", text.lower())
    hashes = re.findall(r"\\b[a-f0-9]{64}\\b", text.lower())
    return {"ips": sorted(set(ips)), "domains": sorted(set(domains)), "hashes": sorted(set(hashes))}
''',
    "ticket_note": '''def format_ticket_note(client: str, ioc: str, verdict: str, next_step: str) -> str:
    """One-line ticket hygiene for MSSP cases."""
    return f"[{client}] IOC {ioc} → {verdict}. Next: {next_step}"
''',
}

DRILLS: list[dict[str, Any]] = [
    {
        "id": "al_extract",
        "title": "Extract IOCs from alert text",
        "difficulty": "easy",
        "kind": "extract",
        "prompt": (
            "Alert text: Host DESK-12 connected to evil-pay.example (203.0.113.9) "
            "hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "sample_text": (
            "Host DESK-12 connected to evil-pay.example (203.0.113.9) "
            "hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "expect_ip": "203.0.113.9",
        "expect_domain": "evil-pay.example",
        "teach": "Scripts pull candidates. You still judge reputation and write the ticket.",
    },
    {
        "id": "al_format",
        "title": "Format a ticket note",
        "difficulty": "easy",
        "kind": "format",
        "prompt": "Client Contoso, IOC 203.0.113.9, verdict suspicious spray source, next block 24h.",
        "client": "Contoso",
        "ioc": "203.0.113.9",
        "verdict": "suspicious spray source",
        "next_step": "block 24h",
        "must_include": ["contoso", "203.0.113.9", "suspicious", "block"],
        "teach": "Automation formats. You still own accuracy of the verdict string.",
    },
    {
        "id": "al_safe",
        "title": "What this track never does",
        "difficulty": "easy",
        "kind": "mcq",
        "prompt": "Which task belongs in Automation Lite?",
        "choices": [
            {"id": "a", "label": "Parse IOCs from alert text for a ticket"},
            {"id": "b", "label": "Write an exploit PoC against a client host"},
            {"id": "c", "label": "Disable MFA for all tenants automatically"},
        ],
        "answer": "a",
        "teach": "Safe enrichment only. No exploit or privilege-bypass automation.",
    },
]


def list_drills() -> list[dict[str, Any]]:
    """Hub cards."""
    return [
        {
            "id": d["id"],
            "title": d["title"],
            "difficulty": d["difficulty"],
            "kind": d["kind"],
        }
        for d in DRILLS
    ]


def get_drill(drill_id: str) -> dict[str, Any] | None:
    """Public drill."""
    for d in DRILLS:
        if d["id"] == drill_id:
            pub = {
                "id": d["id"],
                "title": d["title"],
                "difficulty": d["difficulty"],
                "kind": d["kind"],
                "prompt": d["prompt"],
                "teach": d["teach"],
                "snippets": SNIPPETS,
            }
            if d["kind"] == "extract":
                pub["sample_text"] = d["sample_text"]
            if d["kind"] == "format":
                pub.update({
                    "client": d["client"],
                    "ioc": d["ioc"],
                    "verdict": d["verdict"],
                    "next_step": d["next_step"],
                })
            if d["kind"] == "mcq":
                pub["choices"] = d["choices"]
            return pub
    return None


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Safe IOC extract used by grade + demo."""
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or "")
    domains = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", (text or "").lower())
    hashes = re.findall(r"\b[a-f0-9]{64}\b", (text or "").lower())
    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "hashes": sorted(set(hashes)),
    }


def grade_automation(drill_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Grade extract / format / mcq drills."""
    d = next((x for x in DRILLS if x["id"] == drill_id), None)
    if not d:
        return {"ok": False, "error": "Unknown drill"}

    if d["kind"] == "extract":
        found = extract_iocs(d["sample_text"])
        # Student may paste extracted lists or we auto-check the sample
        user_ips = payload.get("ips") or found["ips"]
        ok_ip = d["expect_ip"] in (user_ips if isinstance(user_ips, list) else [])
        user_doms = payload.get("domains") or found["domains"]
        ok_dom = d["expect_domain"] in (user_doms if isinstance(user_doms, list) else [])
        # Also accept running extract on sample via flag
        if payload.get("ran_extract"):
            ok_ip = d["expect_ip"] in found["ips"]
            ok_dom = d["expect_domain"] in found["domains"]
        pct = (50 if ok_ip else 0) + (50 if ok_dom else 0)
        tips = []
        if not ok_ip:
            tips.append(f"Expected IP {d['expect_ip']}")
        if not ok_dom:
            tips.append(f"Expected domain {d['expect_domain']}")
        if not tips:
            tips.append("IOCs extracted cleanly.")
        return {
            "ok": True,
            "pct": pct,
            "passed": pct >= 70,
            "tips": tips,
            "teach": d["teach"],
            "extracted": found,
            "answer_chips": [
                career_rationale.chip(
                    id="extract",
                    label=f"IP {d['expect_ip']} + domain {d['expect_domain']}",
                    matched=pct >= 70,
                    rationale=d["teach"],
                    title="Why these IOCs",
                    row_label="Correct extract targets",
                ),
            ],
        }

    if d["kind"] == "format":
        note = (payload.get("note") or "").strip()
        low = note.lower()
        hits = [k for k in d["must_include"] if k in low]
        pct = round(100 * len(hits) / max(len(d["must_include"]), 1))
        tips = []
        missing = [k for k in d["must_include"] if k not in low]
        if missing:
            tips.append("Missing: " + ", ".join(missing))
        else:
            tips.append("Ticket line is usable.")
        model = f"[{d['client']}] IOC {d['ioc']} → {d['verdict']}. Next: {d['next_step']}"
        return {
            "ok": True,
            "pct": pct,
            "passed": pct >= 70,
            "tips": tips,
            "teach": d["teach"],
            "model_note": model,
            "answer_chips": [
                career_rationale.chip(
                    id="format",
                    label=model,
                    matched=pct >= 70,
                    rationale=d["teach"],
                    title="Why this ticket shape",
                    row_label="Model note",
                ),
            ],
        }

    if d["kind"] == "mcq":
        ans = (payload.get("choice") or "").strip().lower()
        passed = ans == d["answer"]
        opt = next((c for c in d["choices"] if c["id"] == d["answer"]), None)
        return {
            "ok": True,
            "pct": 100 if passed else 0,
            "passed": passed,
            "tips": [d["teach"] if passed else "Wrong. Safe enrichment only."],
            "teach": d["teach"],
            "answer_chips": [
                career_rationale.chip(
                    id="scope",
                    label=(opt or {}).get("label") or d["answer"],
                    matched=passed,
                    rationale=d["teach"],
                    title="Why this stays in scope",
                    row_label="Correct scope",
                ),
            ],
        }

    return {"ok": False, "error": "Unsupported kind"}
