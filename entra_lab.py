"""
G11 — Entra Conditional Access storyboard (offline, no Azure).

Practice reading a Conditional Access (CA) policy outcome on a sign-in,
then explaining the alert. Original Boundry samples only.
Show me storyboard → Prove it with CA outcome + disposition.
"""

from __future__ import annotations

from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Entra Conditional Access Lab"
TRACK_BLURB = (
    "Practice reading Microsoft Entra ID Conditional Access the way L1 sees it "
    "on M365-heavy clients. You get a sign-in storyboard: who signed in, which "
    "Conditional Access policy applied, and the grant or block outcome. Then you "
    "explain the alert. No Azure portal required."
)

PASS_PCT = 70

PRIMER = [
    {
        "term": "Entra ID",
        "plain": "Microsoft's cloud identity platform (formerly Azure AD). It handles sign-ins, MFA, and Conditional Access for Microsoft 365 and many apps.",
    },
    {
        "term": "Conditional Access (CA)",
        "plain": "An identity policy that grants a session only if conditions pass (user, location, device, app, risk). Think of it as: if these conditions match, then require MFA / require compliant device / block.",
    },
    {
        "term": "Grant control",
        "plain": "What CA demands when conditions match: allow, block, require MFA, require compliant device, or require password change.",
    },
    {
        "term": "CA result",
        "plain": "What happened on this sign-in: success (policy satisfied), failure (blocked or MFA not completed), or not applied (policy did not match).",
    },
    {
        "term": "Legacy authentication",
        "plain": "Old mail/sync protocols that often skip modern MFA. Many CA policies block legacy auth on purpose.",
    },
]


def _case(
    cid: str,
    title: str,
    difficulty: int,
    client: str,
    storyboard: dict[str, Any],
    outcome_id: str,
    disposition: str,
    teach: str,
    checklist: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": cid,
        "title": title,
        "difficulty": difficulty,
        "client": client,
        "storyboard": storyboard,
        "correct_outcome": outcome_id,
        "correct_disposition": disposition,
        "teach": teach,
        "checklist_answers": checklist,
    }


CASES: list[dict[str, Any]] = [
    _case(
        "legacy_auth_block",
        "Legacy IMAP blocked by CA",
        1,
        "Contoso",
        {
            "user": "a.chen@contoso.lab",
            "app": "IMAP (legacy mail client)",
            "ip": "198.51.100.40",
            "location": "Toronto, CA",
            "device": "Unknown / not registered",
            "risk": "None",
            "policy_name": "Block legacy authentication",
            "policy_conditions": "Client apps = Exchange ActiveSync / other clients (legacy)",
            "grant_control": "Block access",
            "signin_result": "Failure",
            "ca_status": "failure",
            "alert_text": (
                "SIEM alert: repeated failed sign-ins for a.chen from mail client. "
                "Ticket asks if this is an attack."
            ),
        },
        "policy_blocked_as_designed",
        "close_expected_policy",
        "CA blocked legacy IMAP on purpose. Document the policy name and close as "
        "expected control, unless volume suggests someone is hammering credentials anyway.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": True,
            "treat_as_account_takeover": False,
        },
    ),
    _case(
        "mfa_fatigue_grant",
        "MFA push spam after CA grant",
        1,
        "NorthPeak",
        {
            "user": "s.reid@northpeak.lab",
            "app": "Office 365 Exchange Online",
            "ip": "203.0.113.77",
            "location": "Unknown / rare geo",
            "device": "Unmanaged browser session",
            "risk": "Medium (unfamiliar location)",
            "policy_name": "Require MFA for medium+ risk",
            "policy_conditions": "Sign-in risk = medium or high; Users = All",
            "grant_control": "Require multifactor authentication",
            "signin_result": "Success (MFA approved on 1 of 14 prompts)",
            "ca_status": "success",
            "alert_text": (
                "User reports phone flooded with MFA prompts overnight. "
                "One prompt was approved. Session is active from rare geo."
            ),
        },
        "mfa_satisfied_but_suspicious",
        "escalate_identity",
        "CA did its job (required MFA) but the user may have approved under fatigue. "
        "Escalate identity: revoke sessions, reset MFA, review the rare IP.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": True,
        },
    ),
    _case(
        "compliant_device_ok",
        "Non-compliant laptop blocked",
        1,
        "Harbor Retail",
        {
            "user": "pos.clerk@harbor.lab",
            "app": "SharePoint Online",
            "ip": "198.51.100.55",
            "location": "Store Wi-Fi",
            "device": "BYOD Android, Intune: noncompliant",
            "risk": "None",
            "policy_name": "Require compliant device for SharePoint",
            "policy_conditions": "Cloud apps = Office 365 SharePoint Online; Devices = All",
            "grant_control": "Require device to be marked compliant",
            "signin_result": "Failure",
            "ca_status": "failure",
            "alert_text": (
                "Help desk ticket: clerk cannot open SharePoint from personal phone. "
                "SOC alert fired on failed CA."
            ),
        },
        "policy_blocked_as_designed",
        "close_expected_policy",
        "Noncompliant BYOD failed a require-compliant-device grant. That is CA working. "
        "Route to IT for enrollment, not IR, unless other risk signals appear.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": False,
        },
    ),
    _case(
        "report_only_miss",
        "Report-only CA did not block",
        2,
        "Contoso",
        {
            "user": "contractor.x@contoso.lab",
            "app": "Azure Portal",
            "ip": "203.0.113.200",
            "location": "Rare geo (practice stub)",
            "device": "Unmanaged",
            "risk": "High",
            "policy_name": "Block high risk (REPORT-ONLY)",
            "policy_conditions": "Sign-in risk = high; State = Report-only (not enforced)",
            "grant_control": "Block access (would apply if enforced)",
            "signin_result": "Success",
            "ca_status": "reportOnly",
            "alert_text": (
                "Identity Protection flagged high-risk success. "
                "CA blade shows the block policy in report-only mode."
            ),
        },
        "report_only_no_enforce",
        "escalate_identity",
        "Report-only means the block did not stop the session. Treat the successful "
        "high-risk sign-in as escalate, and flag that the policy is not enforced yet.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": True,
        },
    ),
    _case(
        "impossible_travel",
        "Impossible travel after VPN success",
        2,
        "NorthPeak",
        {
            "user": "a.morgan@northpeak.lab",
            "app": "Office 365 Exchange Online",
            "ip": "45.77.12.200",
            "location": "Lagos, NG (12 min after Toronto VPN success)",
            "device": "Browser, no device ID",
            "risk": "High (impossible travel)",
            "policy_name": "Require MFA for medium+ risk",
            "policy_conditions": "Sign-in risk = medium or high",
            "grant_control": "Require multifactor authentication",
            "signin_result": "Success (MFA satisfied)",
            "ca_status": "success",
            "alert_text": (
                "Identity Protection: impossible travel. Toronto VPN at 09:00, "
                "Lagos browser session at 09:12 with MFA success."
            ),
        },
        "mfa_satisfied_but_suspicious",
        "escalate_identity",
        "MFA success does not clear impossible travel. Escalate identity: revoke sessions, "
        "confirm with the user, and check whether the Lagos IP is attacker-owned.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": True,
        },
    ),
    _case(
        "guest_b2b_block",
        "Guest B2B blocked from finance app",
        1,
        "Contoso",
        {
            "user": "vendor.ap@partner.example",
            "app": "Contoso Finance App (custom)",
            "ip": "198.51.100.90",
            "location": "Partner HQ",
            "device": "Unmanaged",
            "risk": "None",
            "policy_name": "Block guests from Finance apps",
            "policy_conditions": "Users = All guest users; Cloud apps = Finance App",
            "grant_control": "Block access",
            "signin_result": "Failure",
            "ca_status": "failure",
            "alert_text": (
                "Vendor complains they cannot open the finance app. "
                "SOC sees a CA failure for a guest account."
            ),
        },
        "policy_blocked_as_designed",
        "close_expected_policy",
        "Guest access to a finance app is blocked by design. Close as expected policy and "
        "route the vendor to the business owner for an exception process, not IR.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": False,
        },
    ),
    _case(
        "token_replay_hint",
        "Familiar location, unfamiliar token binding",
        2,
        "Harbor Retail",
        {
            "user": "mgr.store@harbor.lab",
            "app": "Microsoft Teams",
            "ip": "198.51.100.55",
            "location": "Store Wi-Fi (familiar)",
            "device": "Registered, but token claim mismatch stub",
            "risk": "Medium (anomalous token)",
            "policy_name": "Require MFA for medium+ risk",
            "policy_conditions": "Sign-in risk = medium or high",
            "grant_control": "Require multifactor authentication",
            "signin_result": "Success (MFA from different device than session)",
            "ca_status": "success",
            "alert_text": (
                "Risk engine flags possible token replay. Same store IP, but MFA device "
                "and session device claims do not match the normal pattern."
            ),
        },
        "mfa_satisfied_but_suspicious",
        "escalate_identity",
        "Familiar IP alone is not enough when token claims look wrong. Escalate identity "
        "and revoke refresh tokens; do not close as expected CA.",
        {
            "read_policy_name": True,
            "matched_grant_control": True,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": True,
        },
    ),
    _case(
        "named_location_ok",
        "Trusted named location after travel ticket",
        1,
        "Contoso",
        {
            "user": "s.reid@contoso.lab",
            "app": "Azure Portal",
            "ip": "203.0.113.10",
            "location": "Conference hotel (named location: Contoso-Events)",
            "device": "Compliant Intune laptop",
            "risk": "None (named location)",
            "policy_name": "Block high risk (enforced)",
            "policy_conditions": "Sign-in risk = high; exclude Contoso-Events named locations",
            "grant_control": "Block access",
            "signin_result": "Success",
            "ca_status": "notApplied",
            "alert_text": (
                "Travel change ticket CHG-4411 lists this hotel IP range. "
                "Alert fired on geo change before named-location sync completed."
            ),
        },
        "ca_not_related",
        "close_expected_policy",
        "Named location plus change ticket explains the geo. CA did not need to block. "
        "Close with the change reference; watch-only if you still want a short confirm with the traveler.",
        {
            "read_policy_name": True,
            "matched_grant_control": False,
            "legacy_or_weak_client": False,
            "treat_as_account_takeover": False,
        },
    ),
]

OUTCOMES = [
    {
        "id": "policy_blocked_as_designed",
        "label": "CA blocked or failed the sign-in as designed",
        "why": "Grant control blocked legacy, noncompliant, or other matched conditions.",
    },
    {
        "id": "mfa_satisfied_but_suspicious",
        "label": "CA required MFA and it passed, but session still looks hostile",
        "why": "MFA fatigue, rare geo, or user report that a prompt was approved by mistake.",
    },
    {
        "id": "report_only_no_enforce",
        "label": "Policy is report-only, so it did not stop the session",
        "why": "Would-block controls in report-only do not protect; escalate the success.",
    },
    {
        "id": "ca_not_related",
        "label": "Conditional Access is unrelated to this alert",
        "why": "Almost never true when the storyboard shows a named CA policy on the sign-in.",
    },
]

DISPOSITIONS = [
    {
        "id": "close_expected_policy",
        "label": "Close as expected CA enforcement / route to IT",
        "why": "Policy did what admins intended (block legacy, require compliant device).",
    },
    {
        "id": "escalate_identity",
        "label": "Escalate to identity / IR (session risk)",
        "why": "Possible takeover, MFA fatigue, or report-only miss with a live session.",
    },
    {
        "id": "watch_only",
        "label": "Watch only (no close, no escalate)",
        "why": "Weak when user reports MFA spam or high-risk success already exists.",
    },
    {
        "id": "disable_all_ca",
        "label": "Recommend disabling Conditional Access immediately",
        "why": "Wrong L1 move. Tuning CA is an identity-admin decision after escalate.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "read_policy_name",
        "label": "I read the Conditional Access policy name on the storyboard",
    },
    {
        "id": "matched_grant_control",
        "label": "I matched the grant control (block / MFA / compliant / report-only) to the outcome",
    },
    {
        "id": "legacy_or_weak_client",
        "label": "This sign-in used legacy or otherwise weak client auth",
    },
    {
        "id": "treat_as_account_takeover",
        "label": "This looks like possible account takeover or MFA abuse (escalate)",
    },
]


def case_ids() -> list[str]:
    """Ordered case ids for next-scenario rotation."""
    return [c["id"] for c in CASES]


def list_cases() -> list[dict[str, Any]]:
    """Hub cards without full storyboards."""
    return [
        {
            "id": c["id"],
            "title": c["title"],
            "difficulty": c["difficulty"],
            "client": c["client"],
            "teach": c["teach"],
            "policy": c["storyboard"]["policy_name"],
        }
        for c in CASES
    ]


def get_case(case_id: str) -> dict[str, Any] | None:
    """Return one Entra CA case (canonical, no variants)."""
    for c in CASES:
        if c["id"] == case_id:
            return c
    return None


def materialize_case(case_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new user/IP/device text in the storyboard."""
    case = get_case(case_id)
    if not case:
        return None
    return career_instances.materialize_generic(
        case,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["storyboard", "teach", "client"],
        allow_ip=True,
    )


def next_after(case_id: str) -> dict[str, str]:
    """Random different case + fresh seed under /career/entra."""
    return career_instances.next_scenario(case_ids(), case_id, "/career/entra")


def grade_entra(
    case_id: str,
    checklist: dict[str, bool],
    outcome_id: str,
    disposition: str,
) -> dict[str, Any]:
    """Grade checklist + CA outcome reading + disposition."""
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
    outcome_ok = (outcome_id or "").strip() == case["correct_outcome"]
    disp_ok = (disposition or "").strip() == case["correct_disposition"]
    score = hit + (2 if outcome_ok else 0) + (2 if disp_ok else 0)
    total = len(CHECKLIST_ITEMS) + 4
    pct = round(100 * score / total)
    out_meta = next((o for o in OUTCOMES if o["id"] == case["correct_outcome"]), None)
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == case["correct_disposition"]), None
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "outcome_correct": outcome_ok,
        "correct_outcome": case["correct_outcome"],
        "disposition_correct": disp_ok,
        "correct_disposition": case["correct_disposition"],
        "teach": case["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.chip(
                id="outcome",
                label=(out_meta or {}).get("label") or case["correct_outcome"],
                matched=outcome_ok,
                rationale=(
                    f"Why this CA reading: {(out_meta or {}).get('why') or ''} "
                    f"For this case: {case['teach']}"
                ).strip(),
                title="Why this CA outcome",
                row_label="Correct CA outcome",
            ),
            career_rationale.disposition_chip(
                correct_id=case["correct_disposition"],
                label=(disp_meta or {}).get("label") or case["correct_disposition"],
                matched=disp_ok,
                teach=case["teach"],
                why=(disp_meta or {}).get("why") or "",
            ),
        ],
    }
