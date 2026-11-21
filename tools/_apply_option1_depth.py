"""
Apply Option 1 deepening + analogy retune to D2–D5 generators.

D1 is hand-expanded in gen_secplus_d1.py (gold bar). This script rewrites
section bodies / minutes in gen_secplus_d2b.py, d3, d4, d5, and cleans
leftover YouTube-tutor / stem-spam boilerplate in those files.

Run from repo root:
  python tools/_apply_option1_depth.py
  python tools/build_secplus_phase1.py
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def body(
    work: str,
    formal: str,
    beats: str,
    tech: str,
    worked: str,
    how: str,
    trap: str,
    remember: str,
    orient: str = "",
) -> str:
    """Assemble one Show-me section at the Option 1 depth bar."""
    parts = []
    if orient.strip():
        parts.append(orient.strip())
        parts.append("")
    parts.append(f"Where you see this at work: {work.strip()}")
    parts.append("")
    parts.append(f"In Security+ terms, that is {formal.strip()}.")
    parts.append("")
    parts.append(beats.strip())
    parts.append("")
    parts.append("Technical specifics:")
    parts.append(tech.strip())
    parts.append("")
    parts.append("Worked example:")
    parts.append(worked.strip())
    parts.append("")
    parts.append("How to answer on the exam:")
    parts.append(how.strip())
    parts.append("")
    parts.append(f"Common trap: {trap.strip()}")
    parts.append("")
    parts.append(f"Remember: {remember.strip()}")
    # indent like existing generator bodies
    text = "\n".join(parts)
    return "\n".join("                " + ln if ln else "" for ln in text.splitlines())


# lesson_id -> (minutes, [(heading, body_text), ...])
DEPTH: dict[str, tuple[int, list[tuple[str, str]]]] = {}


def put(lid: str, minutes: int, sections: list[tuple[str, str]]) -> None:
    DEPTH[lid] = (minutes, sections)


# ---------------------------------------------------------------------------
# DOMAIN 2
# ---------------------------------------------------------------------------
put(
    "sp_d2_01_threat_actors",
    17,
    [
        (
            "Motivation drives urgency",
            body(
                orient=(
                    "Domain 2 asks you to compare threat actors and motivations. A threat "
                    "actor is who (or what kind of group) is attacking. Motivation is why "
                    "they bother. Motivation changes how fast you escalate."
                ),
                work=(
                    "internet SMB probes on TCP 445 hit your firewall and are DROP. Later "
                    "the same week you find ALLOW tcp/3389 from the internet to PROD-DC01. "
                    "Same ports family, different urgency, because path and asset value differ."
                ),
                formal=(
                    "matching actor class and motivation to the evidence, then choosing "
                    "urgency. You escalate open management paths to crown-jewel systems "
                    "faster than failed commodity noise."
                ),
                beats=(
                    "Actor / motivation map (learn the classes):\n"
                    "  1. Nation-state: persistence, stealth, long dwell, espionage or disruption\n"
                    "  2. Organized crime / ransomware: money; spray → valid creds → encrypt\n"
                    "  3. Hacktivist: disruption or public message\n"
                    "  4. Insider (intentional): privilege abuse, staging data, no ticket admins\n"
                    "  5. Insider (unintentional): CFO clicks Invoice.xlsm; missing travel note\n"
                    "  6. Shadow IT / weak admin: exposed RDP 'just for the vendor'\n"
                    "  7. Script kiddie / commodity: noisy scans that often never get through"
                ),
                tech=(
                    "  - Commodity smell: many DROP rows on 445/3389, no internal follow-on\n"
                    "  - Crime/ransomware smell: identity failures → success → remote access → encryption\n"
                    "  - Insider smell: local admin created off-hours, no CHG, data staging shares\n"
                    "  - You rarely 'prove nation-state' from one SIEM row. Pick the class the\n"
                    "    evidence supports. Do not write an APT novel from a DROP burst."
                ),
                worked=(
                    "Spray against 30 users, then encryption notes on a finance share.\n"
                    "Best motivation class: organized crime / ransomware economics.\n"
                    "Contrast: DROP-only 445 noise with no lateral movement stays commodity\n"
                    "probe. Note the IOC. Do not page like domain compromise."
                ),
                how=(
                    "  1. What path worked or is open?\n"
                    "  2. What asset is at risk (DC, CFO mailbox, HR PC)?\n"
                    "  3. Which motivation fits the evidence without drama?\n"
                    "  4. Escalate to the urgency that path deserves."
                ),
                trap=(
                    "treating every noisy scan as nation-state, or treating ALLOW 3389 to a "
                    "DC like DROP noise. Path open to a crown jewel is not the same class "
                    "as a failed probe."
                ),
                remember="Motivation + path + asset value set urgency, not port noise alone.",
            ),
        ),
        (
            "Talk-track that passes the exam and the interview",
            body(
                work=(
                    "your lead asks if this is APT. You say: evidence looks crime/commodity "
                    "on identity and email paths. You are containing for ransomware stage-1, "
                    "not writing a nation-state novel."
                ),
                formal="evidence-first actor classification under time pressure.",
                beats=(
                    "Hire talk-track beats:\n"
                    "  1. Name the path (identity, email, remote access, supply chain).\n"
                    "  2. Name the likely motivation class that fits.\n"
                    "  3. Name the containment that interrupts money or privilege abuse.\n"
                    "  4. Widen the hypothesis only when evidence disagrees."
                ),
                tech=(
                    "  - Unintentional insider still counts as human risk on the outline.\n"
                    "  - Shadow IT exposing RDP is poorly skilled / unsanctioned admin risk,\n"
                    "    not a compensating control.\n"
                    "  - Hacktivist cues: defacement, loud disruption, public messaging."
                ),
                worked=(
                    "New local admin at 03:14, no ticket. Keep insider or compromised admin "
                    "identity on the table. Do not close as '445 noise' because privilege changed."
                ),
                how=(
                    "  1. Reject movie plots without evidence.\n"
                    "  2. Prefer the class that matches logs and business impact.\n"
                    "  3. Say what you will contain next."
                ),
                trap="closing privileged change as script-kiddie noise because the perimeter is noisy.",
                remember="Pick the class the question actually shows. Contain the path.",
            ),
        ),
    ],
)

put(
    "sp_d2_02_vectors_email_identity",
    17,
    [
        (
            "Vector vs surface",
            body(
                orient=(
                    "A vector is how they got in. An attack surface is what they could touch. "
                    "Mixing those two words is a common miss on the exam."
                ),
                work=(
                    "Invoice.xlsm lands in HR mail. Separately, one seasonal password is tried "
                    "against thirty accounts from one IP. Separately, legacy mail auth creates "
                    "an inbox rule without an MFA prompt."
                ),
                formal=(
                    "email and identity as primary vectors, with attack surface reduction as "
                    "the fix that removes the path."
                ),
                beats=(
                    "Vector map:\n"
                    "  1. Phishing / email: malicious docs, links, BEC vendor impersonation\n"
                    "  2. Identity: password spray, brute force, credential stuffing, missing MFA\n"
                    "  3. Legacy auth: older protocols that often skip modern MFA / CA prompts\n"
                    "  4. Surface shrink: block internet macros, require MFA, disable legacy auth,\n"
                    "     shrink local admin, block inbound management ports"
                ),
                tech=(
                    "  - Spray: one password (or few), many users, often one src_ip, short window\n"
                    "  - Brute: one user, many passwords / failures\n"
                    "  - BEC collection: inbox rule, external forward, finance payment-change language\n"
                    "  - Logs: 4625 bursts, Entra SigninLogs, mailbox audit for New-InboxRule\n"
                    "  - Controls: ASR (Attack Surface Reduction) Office→script, mail gateway,\n"
                    "    Conditional Access, disable basic/legacy auth"
                ),
                worked=(
                    "Password 'Summer2026!' against 30 accounts from one IP = spray, not "
                    "pass-the-hash and not single-user brute. Primary vectors for CFO→Gmail "
                    "via legacy auth = email/identity with weak auth protocol."
                ),
                how=(
                    "  1. Name how entry happened (vector).\n"
                    "  2. Name what was reachable (surface).\n"
                    "  3. Pick the control that closes that path, not a random tool brand."
                ),
                trap=(
                    "calling spray 'brute' or answering USB when the story is clearly mail "
                    "and auth. Another near-miss: more dashboards while legacy auth stays on."
                ),
                remember="Vector = how in. Surface = what they can touch. Close the path.",
            ),
        ),
        (
            "Attack surface reduction that sticks",
            body(
                work=(
                    "you disable macros from the internet, turn off legacy auth, require MFA, "
                    "and remove standing local admin from HR laptops after the third macro incident."
                ),
                formal="attack surface reduction: remove paths attackers love.",
                beats=(
                    "ASR checklist for Boundry-style stories:\n"
                    "  1. Mail: block or sandbox risky attachments; train finance callbacks\n"
                    "  2. Endpoint: stop Office from launching script hosts\n"
                    "  3. Identity: MFA everywhere remote; disable legacy auth\n"
                    "  4. Privilege: least local admin; PAM for admin tasks"
                ),
                tech=(
                    "  - Legacy auth debt explains MFA-not-prompted inbox rules.\n"
                    "  - Seasonal reused passwords make spray cheap.\n"
                    "  - 'Be careful' alone is not surface reduction if excel→powershell still works."
                ),
                worked=(
                    "Best surface shrink for Invoice.xlsm: block internet macros / ASR "
                    "Office→script plus user training. Opening more SMTP relay is the opposite."
                ),
                how=(
                    "  1. Find the open path in the question.\n"
                    "  2. Prefer remove-path answers over detect-only answers when asked to mitigate.\n"
                    "  3. Keep spray vs brute names separate."
                ),
                trap="treating awareness posters as enough while Office→PowerShell still runs.",
                remember="For Boundry-style incidents, start with identity plus email.",
            ),
        ),
    ],
)

put(
    "sp_d2_03_vectors_remote_supply",
    16,
    [
        (
            "Remote access paths",
            body(
                orient="Remote access is its own vector class: RDP, VPN, vendor jump hosts.",
                work=(
                    "firewall shows ALLOW tcp/3389 from 203.0.113.88 to PROD-DC01 with no VPN. "
                    "A vendor jump box still has standing domain admin with no review date."
                ),
                formal=(
                    "remote access and supply-chain / third-party access vectors. Close them "
                    "with path removal and lifecycle, not hope."
                ),
                beats=(
                    "Remote / supply map:\n"
                    "  1. Exposed RDP/SSH management from the internet\n"
                    "  2. VPN without MFA (encrypted tunnel, weak identity)\n"
                    "  3. Vendor/MSP standing privilege\n"
                    "  4. Default or seasonal passwords\n"
                    "  5. Removable media and compromised updaters (less common on Boundry shifts,\n"
                    "     still on the outline)"
                ),
                tech=(
                    "  - RDP = TCP 3389. SSH = TCP 22. SMB = TCP 445.\n"
                    "  - Fix for internet RDP to DC: remove exposure; VPN + MFA + PAM/jump.\n"
                    "  - Default creds and Summer2026!-style reuse feed spray stories.\n"
                    "  - Supply chain: trusted updater or MSP path abused with too much privilege."
                ),
                worked=(
                    "ALLOW tcp/3389 from internet to PROD-DC01 = remote access / exposed "
                    "management plane. Vendor jump with standing domain admin = supply-chain "
                    "/ third-party access risk, not Zero Trust success."
                ),
                how=(
                    "  1. Name the remote path.\n"
                    "  2. Ask if identity strength matches the path (MFA? PAM?).\n"
                    "  3. Prefer remove-exposure answers over detect-only."
                ),
                trap="reframing a firewall ALLOW as 'only phishing,' or calling standing vendor admin a compensating control with no owner or expiry.",
                remember="Remote access and identity are default hypotheses. Widen when evidence disagrees.",
            ),
        ),
        (
            "Supply chain and media",
            body(
                work=(
                    "an MSP account still has prod admin a year after the project ended, or HR "
                    "finds a 'free USB giveaway' that auto-runs when plugged in."
                ),
                formal="supply-chain and removable-media vectors sitting beside remote access on objective 2.2.",
                beats=(
                    "When to widen beyond email/VPN:\n"
                    "  1. Entry evidence does not fit mail or remote auth.\n"
                    "  2. Binary came from a trusted updater channel that looks off.\n"
                    "  3. First execution is from removable media."
                ),
                tech=(
                    "  - Removable media: USB/CD autorun or lure files from reception.\n"
                    "  - Third-party: standing VPN/admin without review dates.\n"
                    "  - Compensating would be documented, owned, time-boxed. Hallway yes is not."
                ),
                worked=(
                    "Infected USB at reception = removable media vector. Still teachable even "
                    "if rare on your shifts. Name the class."
                ),
                how=(
                    "  1. Start with remote + identity hypotheses.\n"
                    "  2. Widen when the entry evidence does not fit.\n"
                    "  3. Pick the mitigation that closes that class."
                ),
                trap="never considering supply chain, or always blaming USB when logs show mail and legacy auth.",
                remember="Name the vector class, then pick the control that closes it.",
            ),
        ),
    ],
)

put(
    "sp_d2_04_vulns_misconfig",
    17,
    [
        (
            "Types that match tickets",
            body(
                orient=(
                    "A vulnerability is a weakness that can be exploited. It is not only a CVE "
                    "number. Misconfiguration and insecure design count."
                ),
                work=(
                    "Nessus ticket SEC-220 lists a CVE on the VPN client. Separately, the "
                    "firewall ALLOW for 3389 to the DC has no CVE at all and is still critical."
                ),
                formal=(
                    "software vulnerabilities, misconfigurations, weak configuration, and "
                    "insecure design as first-class vulnerability types."
                ),
                beats=(
                    "Vulnerability types:\n"
                    "  1. Unpatched software / known CVE\n"
                    "  2. Misconfiguration (ALLOW 3389 to DC; kill switch OFF)\n"
                    "  3. Weak configuration (legacy auth on; NTLM fallback)\n"
                    "  4. Default / abandoned privileged accounts\n"
                    "  5. Insecure design (silent external mail forward with no guardrail)\n"
                    "  6. Zero-day: unknown to vendor; you detect behavior and contain"
                ),
                tech=(
                    "  - CVE = Common Vulnerabilities and Exposures ID. Useful, not required\n"
                    "    for something to be a vuln.\n"
                    "  - Scanner input feeds vuln management. Exposure without CVE still pages.\n"
                    "  - Zero-day response starts with EDR parent/child and containment, not\n"
                    "    guessing a CVE name."
                ),
                worked=(
                    "ALLOW 3389 to DC with no CVE = still a vulnerability (misconfiguration / "
                    "exposure). Legacy auth enabled = weak / insecure configuration. Mailbox "
                    "auto-forward to Gmail with no control = insecure design / missing data control."
                ),
                how=(
                    "  1. Ask: weakness that enables abuse?\n"
                    "  2. Do not require a CVE string.\n"
                    "  3. Prioritize by exploitability and asset value."
                ),
                trap="'no CVE means safe.' Open management ports and protocol debt disagree.",
                remember="No CVE ID does not mean safe. Misconfig can outrank a medium CVE.",
            ),
        ),
        (
            "Zero-day realism and human factors",
            body(
                work=(
                    "EDR shows a new parent/child chain you have never seen. There is no CVE "
                    "in the ticket yet. You isolate and hunt behavior anyway."
                ),
                formal="behavior-first response when the vulnerability name is unknown, plus human-factor weaknesses.",
                beats=(
                    "Also vulnerabilities:\n"
                    "  - Reused seasonal passwords\n"
                    "  - No travel notice process\n"
                    "  - Standing service accounts with admin"
                ),
                tech=(
                    "  - Detect: EDR telemetry, unusual script hosts, odd egress.\n"
                    "  - Contain: isolate host, revoke sessions, block hash/URL.\n"
                    "  - Patch when a fix exists; compensate when it does not."
                ),
                worked=(
                    "Zero-day response starts with behavioural detection and containment. "
                    "Guessing the CVE name is optional. Containing is not."
                ),
                how=(
                    "  1. Name the weakness class.\n"
                    "  2. If unknown vuln, still contain on behavior.\n"
                    "  3. Pair human factors with technical guardrails."
                ),
                trap="waiting for a CVE article before isolating a clearly malicious execution chain.",
                remember="Vulnerability = exploitable weakness. Contain what it does.",
            ),
        ),
    ],
)

put(
    "sp_d2_05_vulns_human",
    16,
    [
        (
            "Humans are in the outline for a reason",
            body(
                orient="Human and process gaps are real vulnerability classes on Security+.",
                work=(
                    "finance pays from a single email without a callback. HR keeps clicking "
                    "macro invoices. A vendor VPN account has no review date. Awareness was "
                    "last updated fourteen months ago."
                ),
                formal="social engineering exposure, shadow IT, and process gaps as vulnerabilities.",
                beats=(
                    "Human / process map:\n"
                    "  1. Social engineering success paths (phishing, BEC pressure)\n"
                    "  2. Password hygiene failures (reused Summer2026!)\n"
                    "  3. Missing travel / verification process\n"
                    "  4. Shadow IT and unsanctioned remote access\n"
                    "  5. No owner / no review date on exceptions"
                ),
                tech=(
                    "  - Process gap creates alert debt (travel login without HR note).\n"
                    "  - Callback on payment-change emails reduces BEC payoff.\n"
                    "  - Tech still required: ASR, MFA, disable legacy auth, DLP forwards."
                ),
                worked=(
                    "CEO travel login without HR note = process gap that forces extra "
                    "validation, not automatic ransomware. Repeat Invoice.xlsm clicks = "
                    "human + missing technical macro controls."
                ),
                how=(
                    "  1. Name the human or process weakness.\n"
                    "  2. Pair coaching with a technical guardrail.\n"
                    "  3. Reject shame-only answers."
                ),
                trap="public shaming as the 'control,' or ignoring process gaps because a firewall exists.",
                remember="Do not shame. Contain, coach, and redesign the path.",
            ),
        ),
        (
            "Contain and redesign",
            body(
                work=(
                    "after an unintentional click you isolate the host, reset the user, add "
                    "ASR, and schedule role-based awareness for finance. You do not dunk on "
                    "them in all-hands."
                ),
                formal="treating unintentional insider risk as a control failure, not a character failure.",
                beats=(
                    "Good response framing:\n"
                    "  1. Contain impact\n"
                    "  2. Coach the person\n"
                    "  3. Add technical guardrails\n"
                    "  4. Fix ownership on the exception that allowed the path"
                ),
                tech=(
                    "  - Near-miss answer on the exam: only mock the clicker.\n"
                    "  - Strong answers: ASR + role training + MFA/legacy fixes."
                ),
                worked=(
                    "Best response for unintentional insider: contain impact, coach, add "
                    "technical guardrails. Disable-all-accounts-forever is overkill theater."
                ),
                how=(
                    "  1. Remove shame-only choices.\n"
                    "  2. Prefer dual-layer fixes (people + tech).\n"
                    "  3. Tie process gaps to owners and review dates."
                ),
                trap="'only fire the analyst' or 'only mock the clicker' when the path is still open.",
                remember="The control failed, including the people process. Fix both layers.",
            ),
        ),
    ],
)

put(
    "sp_d2_06_ioc_identity",
    18,
    [
        (
            "Smell the pattern: spray vs brute",
            body(
                orient=(
                    "An indicator of compromise (IOC) is evidence that abuse may be happening "
                    "or already happened. For identity, read the pattern before you pick a name."
                ),
                work=(
                    "SIEM shows thirty distinct users failing from one IP in eight minutes with "
                    "the same seasonal password. Separately, jsmith has 47 failures then a 4624 "
                    "success."
                ),
                formal="password spray versus brute force, plus travel-login validation.",
                beats=(
                    "Pattern map:\n"
                    "  1. Spray: one src_ip, many users, same/few passwords, short window\n"
                    "  2. Brute: one user, many failures, watch for success\n"
                    "  3. After either: hunt successful logons from the attacking IP\n"
                    "  4. Travel: new country + MFA pass is not automatic true-positive"
                ),
                tech=(
                    "  - Windows 4625 = failed logon. 4624 = success.\n"
                    "  - SPL habit: event_type=logon_failed | stats count by src_ip\n"
                    "  - KQL habit: dcount(UserPrincipalName) by IPAddress on SigninLogs\n"
                    "  - Success after failures is the pivot. Failures are smoke; success is fire."
                ),
                worked=(
                    "30 accounts, one IP, one seasonal password, 10 minutes = password spray. "
                    "47 failures on jsmith then 4624 = hunt the success session hard. "
                    "ceo@ Frankfurt, MFA pass, HR confirms conference = likely FP with documented "
                    "travel validation."
                ),
                how=(
                    "  1. Count users vs failures-per-user.\n"
                    "  2. Name spray or brute.\n"
                    "  3. Hunt success sessions next.\n"
                    "  4. For travel, validate process before FP stamp."
                ),
                trap="closing spray as scanner noise, or calling travel+MFA benign forever with no HR/process check when other BEC clues exist.",
                remember="Spray = breadth. Brute = depth. Always hunt the success.",
            ),
        ),
        (
            "Travel vs spray",
            body(
                work=(
                    "Frankfurt sign-in with MFA and a conference on the calendar versus "
                    "Frankfurt with no travel note, legacy auth, and a new inbox rule."
                ),
                formal="using process context to separate travel false positives from BEC-shaped identity abuse.",
                beats=(
                    "Validation beats:\n"
                    "  1. MFA pass ≠ automatically benign\n"
                    "  2. HR / calendar confirmation supports FP with a note\n"
                    "  3. Legacy auth + mailbox rule + money language = contain"
                ),
                tech=(
                    "  - SigninLogs fields: location, app, client app, legacy vs modern, MFA detail\n"
                    "  - Pair identity IOC with mailbox audit when finance is involved"
                ),
                worked=(
                    "Travel + MFA + HR = FP with a note, not blind trust forever. "
                    "Travel login with MFA but no HR note: validate before FP."
                ),
                how=(
                    "  1. List identity IOCs.\n"
                    "  2. Add process context.\n"
                    "  3. Choose contain vs documented FP."
                ),
                trap="automatic ransomware true-positive from a missing travel note alone.",
                remember="MFA pass does not auto-mean benign if process context is missing.",
            ),
        ),
    ],
)

put(
    "sp_d2_07_ioc_bec",
    17,
    [
        (
            "BEC indicator pack",
            body(
                orient=(
                    "BEC means business email compromise: abusing mail and identity to collect "
                    "information or redirect money."
                ),
                work=(
                    "cfo@ gets a new inbox rule forwarding everything to personal Gmail. Client "
                    "used legacy auth. MFA was not prompted. Finance has a vendor payment-change "
                    "draft waiting."
                ),
                formal="mailbox collection / BEC indicators and identity-first containment.",
                beats=(
                    "BEC IOC pack:\n"
                    "  1. New inbox rule or external forward-all\n"
                    "  2. Strange mail client / legacy auth / MFA skipped\n"
                    "  3. Finance-themed lure or payment-change language\n"
                    "  4. Unusual sign-in location or impossible travel without process"
                ),
                tech=(
                    "  - Contain: revoke sessions, remove rule, reset credentials, escalate\n"
                    "  - Eradicate contributors: disable legacy auth, alert/block external forwards\n"
                    "  - CIA lead impact: confidentiality / collection (mail still 'works')\n"
                    "  - MITRE-ish family: email/mailbox collection"
                ),
                worked=(
                    "First fit mitigation: revoke sessions, remove rule, reset, escalate BEC. "
                    "Poster-only is incomplete. Closing as travel FP is how wire fraud happens."
                ),
                how=(
                    "  1. Recognize the pack.\n"
                    "  2. Contain identity and mailbox persistence first.\n"
                    "  3. Warn finance / use callback process.\n"
                    "  4. Fix protocol debt after the firefight."
                ),
                trap="'email is normal business, close FP' while an external forward-all rule is live.",
                remember="Rule + legacy auth + money language = contain now.",
            ),
        ),
        (
            "Near-miss responses",
            body(
                work="leadership wants only a company-wide poster after confirmed BEC.",
                formal="why awareness alone is incomplete after mailbox persistence.",
                beats=(
                    "After containment:\n"
                    "  1. Finance callback on payment changes\n"
                    "  2. Disable legacy auth\n"
                    "  3. DLP / external forward controls\n"
                    "  4. Role-based awareness for finance"
                ),
                tech=(
                    "  - Payment-change draft after inbox rule = fraud staging\n"
                    "  - External forward-all = confidentiality / collection indicator"
                ),
                worked=(
                    "Awareness-only response to confirmed BEC is incomplete. Needs technical "
                    "identity/mail fixes."
                ),
                how=(
                    "  1. Reject poster-only primary answers.\n"
                    "  2. Prefer revoke/remove/reset.\n"
                    "  3. Add process for finance."
                ),
                trap="opening inbound RDP 'so finance can check the server' during BEC.",
                remember="Contain mailbox persistence first. Awareness comes after, not instead.",
            ),
        ),
    ],
)

put(
    "sp_d2_08_ioc_endpoint",
    17,
    [
        (
            "Encoded PowerShell tell",
            body(
                orient=(
                    "Endpoint indicators show what ran on a host. Parent/child process means "
                    "which program launched which child."
                ),
                work=(
                    "WS-HR-03: excel.exe launches powershell.exe -enc from Invoice.xlsm in email. "
                    "No change ticket. Host still on the LAN."
                ),
                formal="malware execution / living-off-the-land indicators and host isolation.",
                beats=(
                    "Endpoint IOC pack:\n"
                    "  1. Suspicious parent/child (Office → script host)\n"
                    "  2. -enc / encoded command (obfuscation, not encryption)\n"
                    "  3. Unsigned script, odd path, egress after launch\n"
                    "  4. No CHG explaining admin scripting"
                ),
                tech=(
                    "  - EDR tree into the ticket. Preserve evidence.\n"
                    "  - Do not decode malware on your hotspot admin laptop.\n"
                    "  - First containment: isolate host / network contain.\n"
                    "  - Hunt hash across mail gateway and other endpoints."
                ),
                worked=(
                    "excel → powershell -enc from Invoice.xlsm = suspicious execution: isolate. "
                    "'Excel is approved business software' is the classic near-miss close reason."
                ),
                how=(
                    "  1. Read parent/child, not only the child name.\n"
                    "  2. Treat -enc as obfuscation/tradecraft.\n"
                    "  3. Isolate before overnight 'curiosity.'"
                ),
                trap="leaving the host online to see if files encrypt by morning, or closing FP because Office is approved.",
                remember="Approved app ≠ approved child behavior. Isolate first.",
            ),
        ),
        (
            "Approved app near-miss",
            body(
                work="someone argues Excel is on the allow list, so the alert must be wrong.",
                formal="living-off-the-land: trusted binaries used for hostile children.",
                beats=(
                    "Remember:\n"
                    "  - Approved parents can launch malicious children\n"
                    "  - Base64 -enc is not AES confidentiality\n"
                    "  - Containment beats curiosity"
                ),
                tech=(
                    "  - Wrong first move: leave on LAN overnight\n"
                    "  - Right pack: isolate, preserve EDR, escalate, hunt campaign/hash"
                ),
                worked=(
                    "Wrong first IR move after confirmed -enc chain: leave on LAN to watch "
                    "encryption. Watching ransomware finish is not analysis."
                ),
                how=(
                    "  1. Reject 'approved app' as sole close reason.\n"
                    "  2. Prefer isolate + hunt.\n"
                    "  3. Keep encoding vs encryption straight."
                ),
                trap="decoding unknown -enc blobs on a production admin workstation.",
                remember="Parent/child + encoded command + email lure = execution chain.",
            ),
        ),
    ],
)

put(
    "sp_d2_09_ioc_network",
    17,
    [
        (
            "Exposure vs probe",
            body(
                orient="Network indicators tell you whether a path was open, used, or blocked.",
                work=(
                    "one firewall story is DROP bursts on TCP 445 with no internal follow-on. "
                    "Another is ALLOW tcp/3389 from the internet to PROD-DC01."
                ),
                formal="ALLOW versus DROP as different incident classes, plus lateral movement and C2 smells.",
                beats=(
                    "Network IOC map:\n"
                    "  1. Exposure: ALLOW on management ports to crown jewels\n"
                    "  2. Probe: DROP/deny bursts that never get through\n"
                    "  3. Lateral movement: odd admin shares / remote services after phishing\n"
                    "  4. C2 / beaconing: steady odd egress, rare ports, staged binaries calling out"
                ),
                tech=(
                    "  - Pair firewall with EDR and identity. Firewall alone is incomplete.\n"
                    "  - ALLOW means path open or used. DROP means perimeter held for that try.\n"
                    "  - Internet RDP to a DC is critical exposure even with no CVE string."
                ),
                worked=(
                    "Internet SMB 445 DROP, no lateral = commodity probe; note IOC. "
                    "ALLOW 3389 to PROD-DC01 = critical exposure / investigate and remove. "
                    "Auth from HR PC to DC admin shares after phishing = possible lateral movement."
                ),
                how=(
                    "  1. Read ALLOW vs DROP first.\n"
                    "  2. Check asset tier.\n"
                    "  3. Corroborate with host/identity.\n"
                    "  4. Match urgency to path, not to row count."
                ),
                trap="paging DROP noise like domain compromise, or treating ALLOW 3389 as INFO because volume is low.",
                remember="ALLOW means path open or used; DROP means perimeter held.",
            ),
        ),
        (
            "Lateral and C2 smells",
            body(
                work=(
                    "after a phishing click, WS-HR-03 suddenly authenticates to PROD-DC01 admin "
                    "shares, or a new binary beacons every five minutes to a rare port."
                ),
                formal="lateral movement and command-and-control (C2) network indicators.",
                beats=(
                    "Hunt beats:\n"
                    "  1. New east-west admin traffic after phishing\n"
                    "  2. Steady callback rhythm (beaconing)\n"
                    "  3. Escalate and contain the host path"
                ),
                tech=(
                    "  - Best pairing: firewall + EDR/identity context\n"
                    "  - Do not open more ports to 'investigate live'"
                ),
                worked=(
                    "Beaconing ≈ steady suspicious egress / callback pattern. "
                    "Internet RDP to DC with no VPN = critical network exposure indicator."
                ),
                how=(
                    "  1. Name exposure vs probe vs lateral vs C2.\n"
                    "  2. Pick containment that matches.\n"
                    "  3. Corroborate sources."
                ),
                trap="firewall-only forever with no host context on a lateral-looking path.",
                remember="Even one successful path to a crown jewel beats a thousand DROPs.",
            ),
        ),
    ],
)

put(
    "sp_d2_10_mitigate_identity",
    17,
    [
        (
            "Match mitigation to pattern",
            body(
                orient="Mitigation means the control that interrupts the attack path you named.",
                work=(
                    "after spray you want MFA and smart lockout. After BEC you revoke sessions "
                    "and disable legacy auth. You do not answer 'more dashboards' while the path "
                    "stays open."
                ),
                formal="identity and email mitigations matched to spray, brute, and BEC patterns.",
                beats=(
                    "Mitigation map:\n"
                    "  Spray → MFA, smart lockout, block bad IPs, hunt successes, password hygiene\n"
                    "  BEC → revoke sessions, remove rules, disable legacy auth, DLP/external\n"
                    "         forward controls, CA for risky sign-ins, finance callback\n"
                    "  Malware execution → isolate host (not identity-poster theater)"
                ),
                tech=(
                    "  - Purpose of MFA: stolen/guessed passwords become insufficient alone\n"
                    "  - Purpose of disabling legacy auth: force modern auth that can demand MFA/CA\n"
                    "  - External forward block = confidentiality / exfil mitigation\n"
                    "  - Smart lockout: slow attacks while limiting collateral lockouts"
                ),
                worked=(
                    "Primary MFA purpose against spray: make password-only attacks fail more. "
                    "Best BEC technical pair: disable legacy auth + block/alert external forwards. "
                    "Leaving a malware host up to observe encryption is the wrong mitigation."
                ),
                how=(
                    "  1. Name the pattern.\n"
                    "  2. Pick the mitigation that closes that path.\n"
                    "  3. Prefer purpose language over brand names."
                ),
                trap="awareness poster only for open RDP, or detect-only answers when the question asks to mitigate.",
                remember="Purpose first, brand name second. Close the path.",
            ),
        ),
        (
            "Purpose of the technique",
            body(
                work="exam wording says 'what is the purpose of disabling legacy authentication?'",
                formal="explaining why a mitigation exists, in ops language.",
                beats=(
                    "Purpose lines to memorize:\n"
                    "  - MFA raises authentication strength\n"
                    "  - Disabling legacy auth forces modern paths that support MFA/CA\n"
                    "  - Forward controls stop mail leaving\n"
                    "  - Smart lockout slows spray/brute without DOSing the company"
                ),
                tech=(
                    "  - If path is still open, detective-only is incomplete\n"
                    "  - Match control to vector every time"
                ),
                worked=(
                    "Picking 'awareness poster only' for open RDP is wrong: remove the exposure."
                ),
                how=(
                    "  1. Translate purpose → what it stops.\n"
                    "  2. Eliminate answers that ignore the open path.\n"
                    "  3. Keep containment timing straight."
                ),
                trap="choosing a tool that does not interrupt the kill chain in the question.",
                remember="Pick the mitigation that interrupts the kill chain you named.",
            ),
        ),
    ],
)

put(
    "sp_d2_11_mitigate_segment",
    17,
    [
        (
            "Enterprise mitigations that show up in Boundry",
            body(
                orient="Beyond identity, you mitigate with segmentation, hardening, patching, isolation, and monitoring.",
                work=(
                    "you remove internet RDP, put admins on a jump host, turn on ASR so Office "
                    "cannot launch script hosts, patch the VPN client, and isolate a host that "
                    "already ran malware. SIEM still watches, but watching alone is not enough."
                ),
                formal="segmentation, hardening, patching, isolation, and monitoring as mitigation classes.",
                beats=(
                    "Purpose map:\n"
                    "  Segmentation / deny 3389: shrink blast radius, remove exposure\n"
                    "  Hardening / ASR: stop Office → script hosts\n"
                    "  Patching: reduce exploitability of known vulns\n"
                    "  Isolation: corrective containment after execution\n"
                    "  Monitoring (SIEM/EDR): detective layer; necessary, not sufficient alone"
                ),
                tech=(
                    "  - Exposed RDP → remove path / VPN+PAM (not another dashboard)\n"
                    "  - Macro malware → ASR + mail controls + isolate if already running\n"
                    "  - Unpatched VPN → patch/replace, then monitor\n"
                    "  - Monitoring without removing open 3389 = detective coverage on an\n"
                    "    unfixed preventive failure"
                ),
                worked=(
                    "Best mitigation for internet RDP to DC: remove internet RDP; VPN+MFA+jump/PAM; "
                    "segment. Purpose of isolation after malware: corrective stop-spread. "
                    "ASR blocking Office→child script = hardening / preventive endpoint mitigation."
                ),
                how=(
                    "  1. Identify the open path or failed host.\n"
                    "  2. Prefer cheapest reliable interrupt, preferably before execution.\n"
                    "  3. Do not confuse detect with prevent."
                ),
                trap="more SIEM panels as the primary fix for internet RDP to a DC.",
                remember="Interrupt the kill chain at the cheapest reliable step.",
            ),
        ),
        (
            "Pick the fit",
            body(
                work="question offers four mitigations; only one matches the failure class.",
                formal="matching mitigation class to failure class under time pressure.",
                beats=(
                    "Quick fit:\n"
                    "  Path open → remove / segment\n"
                    "  Code ran → isolate\n"
                    "  Known vuln → patch\n"
                    "  Need visibility → monitor (plus a preventive fix if path is open)"
                ),
                tech=(
                    "  - Isolation timing: after suspected/confirmed execution\n"
                    "  - Segmentation purpose: limit blast radius / separate trust tiers"
                ),
                worked=(
                    "When is isolation the right mitigation? After suspected/confirmed execution "
                    "on a host, not instead of tickets forever."
                ),
                how=(
                    "  1. Name failure class.\n"
                    "  2. Eliminate wrong-timing answers.\n"
                    "  3. Choose path-closing control when asked to mitigate exposure."
                ),
                trap="using isolation as a substitute for never writing tickets or never patching.",
                remember="Detect ≠ prevent. Architecture fixes beat detective-only.",
            ),
        ),
    ],
)

def _exec_pack(path: Path) -> None:
    """Execute a pack file with body/put/DEPTH in globals."""
    src = path.read_text(encoding="utf-8")
    # Strip leftover import lines if present.
    src = re.sub(
        r"^from _apply_option1_depth import.*\n",
        "",
        src,
        flags=re.M,
    )
    exec(compile(src, str(path), "exec"), globals())


def _clean_spam(text: str) -> str:
    """Remove leftover YouTube-tutor / stem spam from generators and explains."""
    spam_lines = [
        "Analogy: pause like a good YouTube tutor. One everyday picture first, then the CompTIA term so it sticks.",
        "Analogy: pause like a good YouTube tutor. One everyday picture first, then the CompTIA term so it sticks.\n",
    ]
    out = text
    for s in spam_lines:
        out = out.replace(s, "")
    replacements = [
        (" . Remember: match the control to what the stem shows.", ""),
        ("Remember: match the control to what the stem shows.", ""),
        ("Remember: match the control to what the stem actually shows.", ""),
        ("Watch out: the distractor usually mixes this idea with a nearby lookalike term or skips the step the stem is testing.",
         "Common trap: the wrong answer that looks close usually mixes a nearby lookalike idea or skips the step the question is testing."),
        ("Watch out: the distractor usually mixes this idea with a nearby lookalike term.",
         "Common trap: the wrong answer that looks close usually mixes a nearby lookalike idea."),
        ("Watch out:", "Common trap:"),
    ]
    for old, new in replacements:
        out = out.replace(old, new)
    # Collapse excessive blank lines inside triple-quoted blocks somewhat.
    out = re.sub(r"\n{4,}", "\n\n\n", out)
    return out


def _py_string(s: str) -> str:
    """Format a section body as an indented triple-quoted Python string."""
    # Bodies from body() already include leading indentation spaces per line.
    # Strip that and re-indent consistently for the generator file.
    lines = textwrap.dedent(s).splitlines()
    inner = "\n".join(lines)
    return '"""\n' + textwrap.indent(inner, "                ") + '\n                """'


def _replace_lesson_block(text: str, lesson_id: str, minutes: int, sections: list[tuple[str, str]]) -> str:
    """Replace minutes + sections list for one add(lesson_id, ...) call."""
    # Find the add( "lesson_id" ... pattern and the minutes integer after title.
    # Pattern: "sp_...", "domain", "obj",\n "title", MINUTES,
    pat_min = re.compile(
        rf'("{re.escape(lesson_id)}",\s*"[^"]+",\s*"[^"]+",\s*\n\s*"[^"]+",\s*)(\d+)(,)',
        re.M,
    )
    m = pat_min.search(text)
    if not m:
        raise RuntimeError(f"Could not find minutes for {lesson_id}")
    text = pat_min.sub(rf"\g<1>{minutes}\g<3>", text, count=1)

    # Replace sections array: first [ after key_terms list following this lesson.
    # Strategy: find lesson_id, then find the sections argument which is the list of
    # ("heading", """...""") tuples before the practice list that starts with _mc( or [
    # containing _mc.
    start = text.find(f'"{lesson_id}"')
    if start < 0:
        raise RuntimeError(f"lesson id not found: {lesson_id}")

    # Find "sections" start: after key_terms ], the next [ that contains ("heading"
    # Walk from start to find pattern: ],\n        [\n            ("
    rel = text[start:]
    marker = re.search(r'\],\s*\n\s*\[\s*\n\s*\("', rel)
    if not marker:
        raise RuntimeError(f"Could not find sections start for {lesson_id}")
    sec_start = start + marker.start() + marker.group(0).index("[")

    # Find end of sections list: the ], that precedes practice list starting with _mc or pbq attach.
    # From sec_start, scan for balanced brackets carefully with string awareness.
    i = sec_start
    depth = 0
    in_trip = False
    in_single = False
    in_double = False
    escape = False
    while i < len(text):
        ch = text[i]
        nxt3 = text[i : i + 3]
        if in_trip:
            if nxt3 == '"""':
                in_trip = False
                i += 3
                continue
            i += 1
            continue
        if in_single:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_double = False
            i += 1
            continue
        if nxt3 == '"""':
            in_trip = True
            i += 3
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                sec_end = i + 1
                break
        i += 1
    else:
        raise RuntimeError(f"Could not find sections end for {lesson_id}")

    # Build new sections list source.
    parts = ["["]
    for idx, (heading, bod) in enumerate(sections):
        comma = "," if idx < len(sections) - 1 else ","
        # body() already returns indented content lines; rebuild cleanly
        clean = textwrap.dedent(bod).strip("\n")
        parts.append(f'            ("{heading}", """')
        parts.append(textwrap.indent(clean, "                "))
        parts.append(f'                """){comma}')
    parts.append("        ]")
    new_sec = "\n".join(parts)
    return text[:sec_start] + new_sec + text[sec_end:]


def apply_to_file(path: Path, lesson_ids: list[str]) -> None:
    """Rewrite sections/minutes for lesson_ids in one generator file."""
    text = path.read_text(encoding="utf-8")
    text = _clean_spam(text)
    for lid in lesson_ids:
        if lid not in DEPTH:
            raise RuntimeError(f"Missing DEPTH pack for {lid}")
        minutes, sections = DEPTH[lid]
        text = _replace_lesson_block(text, lid, minutes, sections)
        print(f"  updated {lid} -> {minutes} min, {len(sections)} sections")
    # Final spam clean after rewrites
    text = _clean_spam(text)
    # Update module docstring depth note if present
    if "Voice:" in text and "Option 1" not in text:
        text = text.replace(
            "Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).",
            "Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).\n"
            "Depth: Option 1 ~15-20 min Show-me; work-facing picture + technical specifics.",
            1,
        )
    path.write_text(text, encoding="utf-8")
    print(f"Wrote {path.name}")


def main() -> None:
    # Load D3–D5 packs (D2 already registered above).
    _exec_pack(TOOLS / "_depth_packs_d345.py")
    # D5 tail packs 08–11 live as a string constant to avoid truncation issues.
    import _depth_packs_d5_tail as d5tail

    exec(compile(d5tail.TAIL_SOURCE, "_depth_packs_d5_tail.TAIL_SOURCE", "exec"), globals())

    # Option 1 deepen: overwrite thin D2/D3 then D4/D5 to denser tech/worked/trap (D1 bar).
    _exec_pack(TOOLS / "_depth_packs_d23_thick.py")
    _exec_pack(TOOLS / "_depth_packs_d45_thick.py")
    _exec_pack(TOOLS / "_depth_packs_d5_tail_thick.py")

    counts = {
        "d1": sum(1 for k in DEPTH if k.startswith("sp_d1_")),
        "d2": sum(1 for k in DEPTH if k.startswith("sp_d2_")),
        "d3": sum(1 for k in DEPTH if k.startswith("sp_d3_")),
        "d4": sum(1 for k in DEPTH if k.startswith("sp_d4_")),
        "d5": sum(1 for k in DEPTH if k.startswith("sp_d5_")),
    }
    print("DEPTH packs:", counts, "total", sum(counts.values()))
    expected = {"d2": 11, "d3": 9, "d4": 15, "d5": 11}
    for dom, n in expected.items():
        got = counts[dom]
        if got != n:
            missing = [
                lid
                for lid in re.findall(
                    rf'"((?:sp_{dom})_[^"]+)"',
                    (TOOLS / f"gen_secplus_{dom if dom != 'd2' else 'd2b'}.py").read_text(
                        encoding="utf-8"
                    ),
                )
                if lid not in DEPTH
            ]
            # unique
            seen = []
            for m in missing:
                if m not in seen:
                    seen.append(m)
            raise SystemExit(f"Expected {n} {dom} packs, got {got}. Missing: {seen}")

    targets = [
        (TOOLS / "gen_secplus_d2b.py", [k for k in DEPTH if k.startswith("sp_d2_")]),
        (TOOLS / "gen_secplus_d3.py", [k for k in DEPTH if k.startswith("sp_d3_")]),
        (TOOLS / "gen_secplus_d4.py", [k for k in DEPTH if k.startswith("sp_d4_")]),
        (TOOLS / "gen_secplus_d5.py", [k for k in DEPTH if k.startswith("sp_d5_")]),
    ]
    # Preserve lesson order as in each file
    for path, _ in targets:
        ids = []
        for m in re.finditer(r'\n\s+"(sp_d[2-5]_[^"]+)"', path.read_text(encoding="utf-8")):
            lid = m.group(1)
            if lid not in ids and lid in DEPTH:
                ids.append(lid)
        apply_to_file(path, ids)

    # Preserve denser desk-clue boosts after section rewrite.
    import _boost_secplus_thin as boost

    boost.main()
    print("Done applying Option 1 depth to D2–D5 generators.")
    print("Next: python tools/build_secplus_phase1.py")


if __name__ == "__main__":
    main()
