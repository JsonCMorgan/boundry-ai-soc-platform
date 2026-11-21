"""
G1 — Email header / .eml triage lab.

Show me samples → Help me parse headers → Prove it with disposition.
Original Boundry samples only (not real client mail).
"""

from __future__ import annotations

import email
import email.policy
import re
from email.message import EmailMessage
from typing import Any

import career_instances
import career_rationale

TRACK_TITLE = "Email Triage Lab"
TRACK_BLURB = (
    "Learn to read message headers the way a Tier-1 analyst does: From vs Reply-To, "
    "Authentication-Results (SPF / DKIM / DMARC), urgency language, and disposition. "
    "Use samples or paste a .eml. Terms are defined before they are used."
)

PASS_PCT = 70

# Primer copy (also shown on the hub)
PRIMER = [
    {
        "term": "Header",
        "plain": "Metadata lines at the top of an email (From, To, Reply-To, Received, Authentication-Results).",
    },
    {
        "term": ".eml",
        "plain": "A file that stores one email including headers and body. Analysts ask for the .eml, not a screenshot.",
    },
    {
        "term": "SPF",
        "plain": "Sender Policy Framework: which servers are allowed to send mail for a domain.",
    },
    {
        "term": "DKIM",
        "plain": "DomainKeys Identified Mail: a signature that shows the message was authorized and not altered.",
    },
    {
        "term": "DMARC",
        "plain": "A domain policy for what to do when SPF/DKIM fail, plus reporting.",
    },
    {
        "term": "Reply-To",
        "plain": "Where replies go. Attackers often keep a trusted From display name but set Reply-To to their mailbox.",
    },
]


def _sample(
    sid: str,
    title: str,
    difficulty: int,
    disposition: str,
    teach: str,
    raw: str,
    checklist_answers: dict[str, bool],
) -> dict[str, Any]:
    return {
        "id": sid,
        "title": title,
        "difficulty": difficulty,
        "correct_disposition": disposition,
        "teach": teach,
        "raw": raw.strip() + "\n",
        "checklist_answers": checklist_answers,
    }


SAMPLES: list[dict[str, Any]] = [
    _sample(
        "bec_cfo_wire",
        "CFO wire request (lookalike domain)",
        1,
        "escalate_interaction_unknown",
        "Treat as possible BEC. Confirm headers, auth results, and whether the user interacted before closing.",
        """
Return-Path: <wire@c0ntoso-finance.com>
Received: from mail.c0ntoso-finance.com (203.0.113.44) by mx.clientcorp.example
From: "Alex Morgan, CFO" <alex.morgan@contoso.com>
Reply-To: urgent.wires@proton.me
To: ap.clerk@clientcorp.example
Subject: URGENT: Wire approval needed today - keep confidential
Date: Mon, 3 Oct 2026 08:14:22 -0400
Message-ID: <bec001@c0ntoso-finance.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=fail (sender IP is not authorized) smtp.mailfrom=c0ntoso-finance.com;
    dkim=fail header.d=c0ntoso-finance.com;
    dmarc=fail action=none header.from=contoso.com

Hi,

I need you to process a $48,500 wire to our new vendor before EOD.
Do not discuss on Teams. Reply only to this thread.

Alex
""",
        {
            "from_reply_mismatch": True,
            "auth_fail": True,
            "urgency_secrecy": True,
            "lookalike_or_spoof": True,
        },
    ),
    _sample(
        "vendor_bank_update",
        "Vendor banking update PDF",
        2,
        "escalate_no_click_yet",
        "Vendor bank changes are high-fraud. Fail auth + free Reply-To is enough to escalate even before a click.",
        """
Return-Path: <billing@acme-supplies-secure.com>
From: "ACME Supplies AP" <ap@acme-supplies.com>
Reply-To: banking-updates@gmail.com
To: payables@clientcorp.example
Subject: Action required: Updated banking details for invoice #44102
Date: Tue, 4 Oct 2026 11:02:01 -0400
Message-ID: <vnd44102@acme-supplies-secure.com>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=softfail smtp.mailfrom=acme-supplies-secure.com;
    dkim=none;
    dmarc=fail action=quarantine header.from=acme-supplies.com

Please update our remittance account using the attached form.
Process today to avoid late fees.

ACME AP Team
""",
        {
            "from_reply_mismatch": True,
            "auth_fail": True,
            "urgency_secrecy": True,
            "lookalike_or_spoof": True,
        },
    ),
    _sample(
        "legit_hr_notice",
        "Internal HR benefits notice (clean auth)",
        1,
        "close_benign",
        "Aligned From/Reply-To, SPF/DKIM/DMARC pass, no secrecy pressure. Close as benign with a short note.",
        """
Return-Path: <hr-noreply@clientcorp.example>
From: "ClientCorp HR" <hr-noreply@clientcorp.example>
Reply-To: hr-noreply@clientcorp.example
To: allstaff@clientcorp.example
Subject: Open enrollment reminder - benefits portal
Date: Wed, 5 Oct 2026 09:00:00 -0400
Message-ID: <hr-oe-2026@clientcorp.example>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=pass smtp.mailfrom=clientcorp.example;
    dkim=pass header.d=clientcorp.example;
    dmarc=pass action=none header.from=clientcorp.example

Team,

Open enrollment closes Friday. Use the normal benefits portal link on the intranet.
Questions: submit a ticket to HR Services.

ClientCorp HR
""",
        {
            "from_reply_mismatch": False,
            "auth_fail": False,
            "urgency_secrecy": False,
            "lookalike_or_spoof": False,
        },
    ),
    _sample(
        "payroll_redirect",
        "CHRO payroll redirect",
        2,
        "escalate_interaction_unknown",
        "Payroll diversion is BEC-class. Auth fail + Reply-To mismatch + secrecy = escalate path.",
        """
Return-Path: <payroll@clientcorp-hr.com>
From: "Jordan Lee, CHRO" <jordan.lee@clientcorp.example>
Reply-To: jordan.lee.hr@outlook.com
To: hr.ops@clientcorp.example
Subject: Confidential: Update direct deposit for contractor today
Date: Thu, 6 Oct 2026 07:41:11 -0400
Message-ID: <pay-redirect@clientcorp-hr.com>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=fail smtp.mailfrom=clientcorp-hr.com;
    dkim=fail header.d=clientcorp-hr.com;
    dmarc=fail action=none header.from=clientcorp.example

Please change the direct deposit for contractor ID C-2291 to the account in this thread.
Do not call me. I am in meetings all day.

Jordan
""",
        {
            "from_reply_mismatch": True,
            "auth_fail": True,
            "urgency_secrecy": True,
            "lookalike_or_spoof": True,
        },
    ),
    _sample(
        "o365_cred_harvest",
        "Fake Microsoft 365 password reset",
        1,
        "escalate_no_click_yet",
        "Lookalike login page + fail auth is credential harvest. Escalate even if the user says they did not click yet.",
        """
Return-Path: <noreply@micr0soft-secure.com>
From: "Microsoft Account Team" <account-security@microsoft.com>
Reply-To: reset@micr0soft-secure.com
To: j.patel@clientcorp.example
Subject: Unusual sign-in activity - verify your password
Date: Fri, 7 Oct 2026 16:22:00 -0400
Message-ID: <o365-harv@micr0soft-secure.com>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=fail smtp.mailfrom=micr0soft-secure.com;
    dkim=fail header.d=micr0soft-secure.com;
    dmarc=fail action=none header.from=microsoft.com

We detected a sign-in from a new device. Verify within 30 minutes or your mailbox will be locked:
https://micr0soft-secure.com/login

Microsoft Account Team
""",
        {
            "from_reply_mismatch": True,
            "auth_fail": True,
            "urgency_secrecy": True,
            "lookalike_or_spoof": True,
        },
    ),
    _sample(
        "internal_forward_rule",
        "Compromised mailbox auto-forward notice",
        2,
        "escalate_interaction_unknown",
        "Auth can pass when the mailbox is already compromised. Secrecy + external forward pattern still means escalate identity, not close as clean mail.",
        """
Return-Path: <j.patel@clientcorp.example>
From: "J Patel" <j.patel@clientcorp.example>
Reply-To: j.patel@clientcorp.example
To: finance.shared@clientcorp.example
Subject: FW: Q3 invoices - please process quietly
Date: Sat, 8 Oct 2026 02:11:44 -0400
Message-ID: <fwd-rule@clientcorp.example>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=pass smtp.mailfrom=clientcorp.example;
    dkim=pass header.d=clientcorp.example;
    dmarc=pass action=none header.from=clientcorp.example
X-MS-Exchange-Organization-AutoForwarded: true
X-Boundry-Note: Inbox rule forwards copies to invoices.dump@proton.me

Team - handle these invoices tonight. Do not loop in managers.

J
""",
        {
            "from_reply_mismatch": False,
            "auth_fail": False,
            "urgency_secrecy": True,
            "lookalike_or_spoof": False,
        },
    ),
    _sample(
        "qr_phish_invoice",
        "QR code invoice (quishing)",
        2,
        "escalate_no_click_yet",
        "QR phishing skips URL rewrite. Fail auth + urgency + external QR target is escalate; coach the user not to scan.",
        """
Return-Path: <billing@acme-inv0ice.net>
From: "ACME Billing" <billing@acme-supplies.com>
Reply-To: pay@acme-inv0ice.net
To: ap.clerk@clientcorp.example
Subject: Invoice #99021 past due - scan to pay
Date: Sun, 9 Oct 2026 10:05:00 -0400
Message-ID: <qr-inv@acme-inv0ice.net>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=fail smtp.mailfrom=acme-inv0ice.net;
    dkim=none;
    dmarc=fail action=quarantine header.from=acme-supplies.com

Your balance is past due. Scan the QR code in the attached PDF to pay today.
Do not forward this message.

ACME Billing
""",
        {
            "from_reply_mismatch": True,
            "auth_fail": True,
            "urgency_secrecy": True,
            "lookalike_or_spoof": True,
        },
    ),
    _sample(
        "vendor_newsletter",
        "Known vendor newsletter (clean)",
        1,
        "close_benign",
        "Aligned identity, pass auth, no secrecy pressure, marketing tone. Close benign; no escalate for a normal newsletter.",
        """
Return-Path: <news@acme-supplies.com>
From: "ACME Supplies" <news@acme-supplies.com>
Reply-To: news@acme-supplies.com
To: ap.clerk@clientcorp.example
Subject: October product updates from ACME
Date: Mon, 10 Oct 2026 08:00:00 -0400
Message-ID: <news-oct@acme-supplies.com>
Content-Type: text/plain; charset="utf-8"
Authentication-Results: mx.clientcorp.example;
    spf=pass smtp.mailfrom=acme-supplies.com;
    dkim=pass header.d=acme-supplies.com;
    dmarc=pass action=none header.from=acme-supplies.com

Hello,

Here are this month's catalog updates. Unsubscribe anytime via the portal link on our site.

ACME Marketing
""",
        {
            "from_reply_mismatch": False,
            "auth_fail": False,
            "urgency_secrecy": False,
            "lookalike_or_spoof": False,
        },
    ),
]

DISPOSITIONS = [
    {
        "id": "close_benign",
        "label": "Close as benign / expected",
        "why": "Auth looks good, no mismatch, no pressure to bypass process.",
    },
    {
        "id": "escalate_no_click_yet",
        "label": "Escalate / contain path (no user click confirmed yet)",
        "why": "Fraud indicators present; block/report even if interaction unknown.",
    },
    {
        "id": "escalate_interaction_unknown",
        "label": "Escalate as possible compromise (interaction unknown or likely)",
        "why": "High-impact BEC pattern; treat as compromise until proven otherwise.",
    },
    {
        "id": "user_coach_only",
        "label": "Coach user and close without header review",
        "why": "Wrong for Tier-1: you must inspect the message first.",
    },
]

CHECKLIST_ITEMS = [
    {
        "id": "from_reply_mismatch",
        "label": "From display/domain and Reply-To do not match a trusted pattern",
    },
    {
        "id": "auth_fail",
        "label": "SPF and/or DKIM and/or DMARC show fail / softfail / none (not a clean pass)",
    },
    {
        "id": "urgency_secrecy",
        "label": "Urgency or secrecy language (today, confidential, do not tell anyone)",
    },
    {
        "id": "lookalike_or_spoof",
        "label": "Lookalike domain, spoofed brand, or free-mail Reply-To on a business ask",
    },
]


def sample_ids() -> list[str]:
    """Ordered sample ids for next-scenario rotation."""
    return [s["id"] for s in SAMPLES]


def list_samples() -> list[dict[str, Any]]:
    """Hub cards without raw bodies."""
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "difficulty": s["difficulty"],
            "teach": s["teach"],
        }
        for s in SAMPLES
    ]


def get_sample(sample_id: str) -> dict[str, Any] | None:
    """Return one sample including raw .eml text (canonical, no variants)."""
    for s in SAMPLES:
        if s["id"] == sample_id:
            return s
    return None


def materialize_sample(sample_id: str, seed: str | None = None) -> dict[str, Any] | None:
    """Variant instance: new names, amounts, message ids; auth pattern unchanged."""
    sample = get_sample(sample_id)
    if not sample:
        return None
    # Keep lookalike/auth domains stable so SPF/DKIM teaching stays valid.
    return career_instances.materialize_generic(
        sample,
        seed,
        host_key=None,
        user_key=None,
        text_keys=["raw", "teach"],
        allow_ip=True,
    )


def next_after(sample_id: str) -> dict[str, str]:
    """Random different sample + fresh seed under /career/email."""
    return career_instances.next_scenario(sample_ids(), sample_id, "/career/email")


def parse_eml(raw: str) -> dict[str, Any]:
    """
    Parse .eml / header text into analyst-facing fields.
    Works on pasted headers or full messages.
    """
    text = (raw or "").strip()
    if not text:
        return {"ok": False, "error": "Paste an email or headers first."}

    # email.parser wants a blank line before body; add one if headers-only.
    if "\n\n" not in text and not text.lower().startswith("begin "):
        text = text + "\n\n"

    try:
        msg = email.message_from_string(text, policy=email.policy.default)
    except Exception as exc:
        return {"ok": False, "error": f"Could not parse message: {exc}"}

    if not isinstance(msg, EmailMessage) and not hasattr(msg, "get"):
        return {"ok": False, "error": "Could not parse message."}

    auth = msg.get("Authentication-Results") or msg.get("Authentication-Results".lower()) or ""
    auth_l = auth.lower()
    spf = _auth_token(auth_l, "spf")
    dkim = _auth_token(auth_l, "dkim")
    dmarc = _auth_token(auth_l, "dmarc")

    frm = msg.get("From") or ""
    reply = msg.get("Reply-To") or ""
    subject = msg.get("Subject") or ""
    body = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_content()
                    break
        else:
            body = msg.get_content() if hasattr(msg, "get_content") else str(msg.get_payload())
    except Exception:
        body = ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    body = str(body or "")[:2000]

    from_addr = _extract_addr(frm)
    reply_addr = _extract_addr(reply) if reply else ""
    mismatch = bool(reply_addr) and reply_addr.lower() != from_addr.lower()
    # Also flag when domains differ
    if from_addr and reply_addr:
        if _domain(from_addr) != _domain(reply_addr):
            mismatch = True

    urgency = bool(
        re.search(
            r"\b(urgent|asap|today|eod|confidential|do not (tell|call|discuss)|keep confidential)\b",
            f"{subject}\n{body}",
            re.I,
        )
    )

    return {
        "ok": True,
        "from": frm,
        "from_addr": from_addr,
        "reply_to": reply or "(none)",
        "reply_addr": reply_addr or "",
        "to": msg.get("To") or "",
        "subject": subject,
        "date": msg.get("Date") or "",
        "message_id": msg.get("Message-ID") or "",
        "return_path": msg.get("Return-Path") or "",
        "authentication_results": auth or "(none found — ask for full headers)",
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "from_reply_mismatch": mismatch,
        "auth_fail": _is_auth_fail(spf, dkim, dmarc),
        "urgency_secrecy": urgency,
        "body_preview": body[:600],
    }


def _extract_addr(value: str) -> str:
    m = re.search(r"<([^>]+)>", value or "")
    if m:
        return m.group(1).strip()
    return (value or "").strip()


def _domain(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower()


def _auth_token(auth_l: str, key: str) -> str:
    m = re.search(rf"{key}\s*=\s*([a-z0-9]+)", auth_l or "")
    return m.group(1) if m else "unknown"


def _is_auth_fail(spf: str, dkim: str, dmarc: str) -> bool:
    bad = {"fail", "softfail", "none", "neutral", "permerror", "temperror"}
    # unknown alone is weak; treat fail/softfail/none as fail signals
    vals = {spf, dkim, dmarc}
    if vals & {"fail", "softfail", "none"}:
        return True
    if "pass" in vals and not (vals & bad):
        return False
    return "pass" not in vals


def grade_triage(
    sample_id: str,
    checklist: dict[str, bool],
    disposition: str,
) -> dict[str, Any]:
    """Grade checklist + disposition against a known sample."""
    sample = get_sample(sample_id)
    if not sample:
        return {"ok": False, "error": "Unknown sample"}
    answers = sample["checklist_answers"]
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
    disp_ok = (disposition or "").strip() == sample["correct_disposition"]
    # Checklist 4 pts + disposition 2 pts
    score = hit + (2 if disp_ok else 0)
    total = len(CHECKLIST_ITEMS) + 2
    pct = round(100 * score / total)
    disp_meta = next(
        (d for d in DISPOSITIONS if d["id"] == sample["correct_disposition"]),
        None,
    )
    return {
        "ok": True,
        "pct": pct,
        "passed": pct >= PASS_PCT,
        "checklist": items,
        "disposition_correct": disp_ok,
        "correct_disposition": sample["correct_disposition"],
        "teach": sample["teach"],
        "score": score,
        "total": total,
        "answer_chips": [
            career_rationale.disposition_chip(
                correct_id=sample["correct_disposition"],
                label=(disp_meta or {}).get("label") or sample["correct_disposition"],
                matched=disp_ok,
                teach=sample["teach"],
                why=(disp_meta or {}).get("why") or "",
            ),
        ],
    }
