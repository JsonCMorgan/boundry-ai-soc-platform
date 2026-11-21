"""
Comms Gym (G15) — draft user / client / escalate notes for desk + interview soft skills.

Scenarios are Practice-only. Grade on tone, facts, next action, and no overclaim.
"""

from __future__ import annotations

from typing import Any

import career_rationale

TRACK_TITLE = "Comms Gym"
TRACK_BLURB = (
    "Practice the notes that fail interviews and desks: user callbacks, client updates, "
    "and Tier-2 escalate handoffs. Short, factual, no false certainty."
)

PRIMER = [
    {
        "term": "User callback",
        "plain": "A clear message to the affected person: what happened, what to do now, what you need from them.",
    },
    {
        "term": "Client update",
        "plain": "A short status for the customer or VIP stakeholder: impact, actions taken, next step, no jargon dump.",
    },
    {
        "term": "Escalate note",
        "plain": "What Tier-2 / IR needs: summary, evidence, what you already tried, what you need them to do.",
    },
]

AUDIENCES = [
    {"id": "user", "label": "User callback"},
    {"id": "client", "label": "Client / VIP update"},
    {"id": "escalate", "label": "Escalate to Tier-2"},
]

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "cm_spray_user",
        "title": "Password spray hit — user locked out",
        "audience": "user",
        "difficulty": "easy",
        "facts": [
            "Account jsmith locked after many failed logons from one IP.",
            "No successful logon yet.",
            "You reset the password and require MFA re-register.",
        ],
        "must_include": ["reset", "mfa", "do not", "password"],
        "must_avoid": ["definitely hacked", "ransomware", "ignore this"],
        "good_shape": (
            "Hi Jordan — your account was locked after many failed sign-in attempts. "
            "We reset your password and you must set up MFA again before access returns. "
            "Do not share codes with anyone. Reply if you did not request a reset."
        ),
        "teach": "Reassure + next action. Do not claim full compromise without success evidence.",
    },
    {
        "id": "cm_bec_client",
        "title": "BEC forward rule — client VIP update",
        "audience": "client",
        "difficulty": "medium",
        "facts": [
            "CFO mailbox had an external forward rule created today.",
            "Rule removed; sessions revoked.",
            "Finance asked to callback on any payment-change emails.",
        ],
        "must_include": ["forward", "removed", "finance", "callback"],
        "must_avoid": ["100% safe", "no further risk", "ignore"],
        "good_shape": (
            "Update for Contoso: we found and removed an external email forward on the CFO mailbox, "
            "revoked active sessions, and asked Finance to use callback verification on payment changes. "
            "We are monitoring for related activity and will send a follow-up if impact expands."
        ),
        "teach": "State action taken + business control. Avoid promising zero residual risk.",
    },
    {
        "id": "cm_edr_escalate",
        "title": "EDR mass rename — escalate to Tier-2",
        "audience": "escalate",
        "difficulty": "medium",
        "facts": [
            "Harbor WH-PC07: ransom-note filename + rapid renames.",
            "Host isolated via EDR.",
            "Hash enrichment pending; no restore started.",
        ],
        "must_include": ["isolated", "harbor", "hash", "need"],
        "must_avoid": ["false positive", "user error only", "all clear"],
        "good_shape": (
            "Escalate Harbor WH-PC07: CRITICAL ransomware indicators (note file + mass renames). "
            "Host isolated. Please take IR ownership for forensics and recovery. "
            "Need: hash verdict, backup integrity check, and go/no-go on rebuild. "
            "I have not started restores."
        ),
        "teach": "Evidence + containment done + clear ask. Do not close as FP.",
    },
    {
        "id": "cm_fp_user",
        "title": "Travel login — validate with user",
        "audience": "user",
        "difficulty": "easy",
        "facts": [
            "Successful MFA login from Toronto while calendar says vacation in Vancouver.",
            "No malware alerts.",
            "Need user to confirm travel.",
        ],
        "must_include": ["confirm", "travel", "mfa", "reply"],
        "must_avoid": ["you were hacked", "ransomware", "ignore"],
        "good_shape": (
            "Hi Sam — we saw a successful MFA sign-in from Toronto during your listed Vancouver travel. "
            "Please confirm if that was you. If not, reply immediately and we will revoke sessions."
        ),
        "teach": "Ask to validate. Do not accuse or dismiss.",
    },
    {
        "id": "cm_vuln_client",
        "title": "Critical VPN CVE — client status",
        "audience": "client",
        "difficulty": "hard",
        "facts": [
            "Internet-facing VPN has an active exploit in the wild.",
            "Change window proposed tonight 22:00–23:00 ET.",
            "Compensating: geo-restrict admin until patched.",
        ],
        "must_include": ["vpn", "patch", "tonight", "compensat"],
        "must_avoid": ["already breached", "no need to patch", "ignore"],
        "good_shape": (
            "NorthPeak status: your internet VPN has a critical vulnerability with active exploit "
            "activity industry-wide. We propose patching tonight 22:00–23:00 ET and have applied "
            "temporary admin geo-restrictions. Please approve the window or propose an alternate."
        ),
        "teach": "Business impact + ask for approval. No breach claim without evidence.",
    },
    {
        "id": "cm_phish_escalate",
        "title": "Quishing report — escalate with evidence",
        "audience": "escalate",
        "difficulty": "hard",
        "facts": [
            "Three users scanned parking-lot QR; same evil domain.",
            "One entered MFA code; sessions revoked.",
            "URL blocked at gateway; need hunting for other victims.",
        ],
        "must_include": ["qr", "mfa", "blocked", "hunt"],
        "must_avoid": ["only email phishing", "all clear", "ignore phones"],
        "good_shape": (
            "Escalate quishing cluster: parking QR → pay-evil.example, three reporters, "
            "one MFA code entry (sessions revoked). Gateway URL blocked. "
            "Need Tier-2 hunt for other victims and mail/SMS lookalikes. "
            "Practice note: vector is QR/image-based, not attachment macros."
        ),
        "teach": "Name the channel correctly. Ask for hunt scope.",
    },
]


def list_scenarios() -> list[dict[str, Any]]:
    """Public scenario cards for hub."""
    out = []
    for s in SCENARIOS:
        out.append({
            "id": s["id"],
            "title": s["title"],
            "audience": s["audience"],
            "audience_label": next(
                (a["label"] for a in AUDIENCES if a["id"] == s["audience"]), s["audience"]
            ),
            "difficulty": s["difficulty"],
            "fact_count": len(s.get("facts") or []),
        })
    return out


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    """Return full scenario or None."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None


def grade_draft(scenario_id: str, draft: str) -> dict[str, Any]:
    """Grade a drafted note. Returns ok/pct/passed/feedback."""
    sc = get_scenario(scenario_id)
    if not sc:
        return {"ok": False, "error": "Unknown scenario"}
    text = (draft or "").strip()
    if len(text) < 40:
        return {"ok": False, "error": "Draft too short. Aim for 3–6 clear sentences."}

    low = text.lower()
    hits = [k for k in sc["must_include"] if k in low]
    avoids = [k for k in sc["must_avoid"] if k in low]
    include_score = round(100 * len(hits) / max(len(sc["must_include"]), 1))
    avoid_penalty = min(40, 15 * len(avoids))
    length_ok = 40 <= len(text) <= 900
    tone_ok = not any(x in low for x in ("lol", "idk", "whatever", "stupid"))
    pct = include_score - avoid_penalty
    if length_ok:
        pct += 5
    if tone_ok:
        pct += 5
    pct = max(0, min(100, pct))
    passed = pct >= 70 and not avoids

    tips = []
    missing = [k for k in sc["must_include"] if k not in low]
    if missing:
        tips.append("Add these facts/ideas: " + ", ".join(missing[:4]))
    if avoids:
        tips.append("Remove overclaim / bad phrasing: " + ", ".join(avoids[:3]))
    if len(text) > 900:
        tips.append("Tighten: stakeholder notes should stay short.")
    if not tips:
        tips.append("Clear and usable. Compare with the model note for polish.")

    return {
        "ok": True,
        "pct": pct,
        "passed": passed,
        "hits": hits,
        "avoids": avoids,
        "tips": tips,
        "model_note": sc["good_shape"],
        "teach": sc["teach"],
        "audience": sc["audience"],
        "answer_chips": [
            career_rationale.chip(
                id="model_note",
                label="Model note shape (compare)",
                matched=passed,
                rationale=f"{sc['teach']} Model: {sc['good_shape']}",
                title="Why this note shape",
                row_label="Correct note approach",
            ),
        ],
    }
