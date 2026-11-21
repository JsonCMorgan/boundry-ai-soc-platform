"""
Interview Walkthrough Gym — Guided → Coached → Live.

Training wheels for Jason (no SOC floor experience yet):
  Guided  — interactive step cards, pick-the-best phrase, show-me reveals
  Coached — you write each step; hints + model answer after submit
  Live    — 120s timer, all steps, Ollama rubric (unlock after Guided set)

Investigation skeleton (hiring-manager standard):
  validate → context → analyze → correlate → decide → change_mind
"""

from __future__ import annotations

from typing import Any

TRACK_TITLE = "Interview Walkthrough Gym"
TRACK_BLURB = (
    "Practice saying investigations out loud the way hiring managers test — "
    "with training wheels first, then your own words, then a timed Live round."
)

# Modes (order matters for unlock UX)
MODES = ("guided", "coached", "live")
LIVE_SECONDS = 120
GUIDED_PASS_TO_UNLOCK_COACHED = True  # finish all scenarios in Guided once

STEPS: list[dict[str, str]] = [
    {
        "id": "validate",
        "label": "1. Validate",
        "ask": "Is this alert real data — or junk / misconfig?",
    },
    {
        "id": "context",
        "label": "2. Context",
        "ask": "Who / what asset? What is normal for them?",
    },
    {
        "id": "analyze",
        "label": "3. Analyze",
        "ask": "What specifically looks wrong in the indicator?",
    },
    {
        "id": "correlate",
        "label": "4. Correlate",
        "ask": "What else would you search in a wider window?",
    },
    {
        "id": "decide",
        "label": "5. Decide",
        "ask": "Close, continue, or escalate — and why?",
    },
    {
        "id": "change_mind",
        "label": "6. Change my mind",
        "ask": "What new evidence would flip your decision?",
    },
]

# ── Eight high-frequency Tier-1 scenarios ─────────────────────────────────────
SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "phishing_bec",
        "order": 1,
        "title": "Phishing / BEC wire request",
        "tag": "Email",
        "difficulty": 1,
        "prompt": (
            "A finance employee forwards an email claiming to be from the CFO "
            "asking them to wire $50,000 urgently. Walk me through your investigation."
        ),
        "why_hm": "Phishing/BEC is one of the most common Tier-1 interview walkthroughs.",
        "guided": {
            "validate": {
                "teach": "Treat this as possible BEC, not just spam. Confirm the ticket has the full email (headers + body), not a screenshot-only rumour.",
                "choices": [
                    "Escalate to IR on the dollar amount alone before collecting the original message",
                    "Ask for full headers + original .eml before deciding",
                    "Coach the reporter on phishing red flags and close without inspecting the message",
                ],
                "answer_idx": 1,
                "example": "I'd pull the full email and headers first so I'm investigating real message data, not a paraphrase.",
            },
            "context": {
                "teach": "Who is the user? Do they normally get CFO mail? Is the CFO travelling? What's the approval process for wires?",
                "choices": [
                    "Confirm the reporter is in finance, then treat the request as in-policy",
                    "Message the CFO on Teams to verify before reviewing contact patterns or wire process",
                    "Check role, normal CFO contact patterns, and wire-approval process",
                ],
                "answer_idx": 2,
                "example": "I'd confirm the reporter's role, whether CFO emails are normal for them, and what the business wire-approval process requires.",
            },
            "analyze": {
                "teach": "Lookalike domains, Reply-To mismatch, SPF/DKIM/DMARC fails, urgency + secrecy language, link/display mismatch.",
                "choices": [
                    "Headers auth + From/Reply-To + urgency/authority pressure",
                    "Prioritize company logo and professional signature over auth results",
                    "Focus on wire amount and urgency wording ahead of From/Reply-To checks",
                ],
                "answer_idx": 0,
                "example": "I'd check SPF/DKIM/DMARC, From vs Reply-To, lookalike domains, and urgency language asking to bypass normal approval.",
            },
            "correlate": {
                "teach": "Search gateway for same campaign; check if user clicked/opened; check recent logins for the user.",
                "choices": [
                    "Reset the reporter's password first, then search the gateway if time allows",
                    "Send a company-wide phishing warning before scoping who else received it",
                    "Search who else got it + any clicks + recent auth for the user",
                ],
                "answer_idx": 2,
                "example": "I'd search email gateway logs for the same subject/sender, ask if they clicked, and review their recent sign-ins.",
            },
            "decide": {
                "teach": "No click → document + block/report. Click or creds entered → escalate (reset, revoke sessions).",
                "choices": [
                    "Close as spam if headers look clean, even if they already clicked the link",
                    "Escalate if interaction/creds; else document, block, close with notes",
                    "Escalate every BEC report to legal before any block or documentation",
                ],
                "answer_idx": 1,
                "example": "If they didn't interact, I'd document, block the sender/URL, and close. If they clicked or entered credentials, I'd escalate for reset and session revoke.",
            },
            "change_mind": {
                "teach": "Hiring managers love humility — name what would flip you.",
                "choices": [
                    "Evidence of click, attachment open, or credential entry",
                    "Only if the wire transfer has already left the bank",
                    "Only if a second finance user opens an identical ticket",
                ],
                "answer_idx": 0,
                "example": "I'd escalate immediately if we found clicks, opens, or credential entry — that changes it from blocked attempt to possible compromise.",
            },
        },
        "model": {
            "validate": "Confirm we have the original email/headers and that this is a real reported message.",
            "context": "Finance user; wire process normally needs dual approval; CFO spoof is high-impact.",
            "analyze": "Check auth results, Reply-To, lookalike domain, urgency/secrecy language.",
            "correlate": "Campaign search in gateway; user click history; recent mailbox/auth anomalies.",
            "decide": "No interaction → block + document. Interaction → escalate for identity containment.",
            "change_mind": "Any click, credential entry, or second victim reporting the same lure.",
        },
    },
    {
        "id": "impossible_travel",
        "order": 2,
        "title": "Suspicious / impossible travel login",
        "tag": "Identity",
        "difficulty": 1,
        "prompt": (
            "Your SIEM fires: user jsmith logged in from Romania at 3 AM local time. "
            "jsmith is a marketing coordinator in Chicago. What do you do?"
        ),
        "why_hm": "Impossible travel / odd geo login is a staple identity triage question.",
        "guided": {
            "validate": {
                "teach": "Confirm account exists, timestamp timezone, and that geo isn't a noisy VPN exit.",
                "choices": [
                    "Disable the account and force MFA reset before confirming login success",
                    "Close as expected remote work because marketing often travels",
                    "Confirm success vs fail, MFA, and geo reliability first",
                ],
                "answer_idx": 2,
                "example": "I'd validate whether the login succeeded, if MFA passed, and whether the geo source is trustworthy.",
            },
            "context": {
                "teach": "Normal countries, hours, VPN use, approved travel.",
                "choices": [
                    "Pull 30-day login baseline for jsmith",
                    "Trust the alert's geo label without reviewing prior login history",
                    "Ask jsmith on Teams for a yes/no and pause until they reply",
                ],
                "answer_idx": 0,
                "example": "I'd pull jsmith's recent login history — usual countries, hours, and VPN patterns.",
            },
            "analyze": {
                "teach": "Success? MFA? Datacenter IP? Concurrent Chicago activity?",
                "choices": [
                    "Escalate solely because Romania is unusual for the role",
                    "Success + MFA + IP type + concurrent sessions",
                    "Skip MFA review if the geo looks impossible on its face",
                ],
                "answer_idx": 1,
                "example": "I'd check success/fail, MFA, whether the IP is residential/VPN/datacenter, and concurrent activity from Chicago.",
            },
            "correlate": {
                "teach": "Password changes, mailbox rules, new devices, file downloads nearby in time.",
                "choices": [
                    "Search password/mailbox/device changes in the same window",
                    "Limit correlation to that single login event for speed",
                    "Open a malware scan on the Chicago workstation before identity checks",
                ],
                "answer_idx": 0,
                "example": "I'd correlate password changes, inbox rules, new device registrations, and downloads around that login.",
            },
            "decide": {
                "teach": "Weird success without MFA/VPN story → escalate. VPN/FP pattern → document close.",
                "choices": [
                    "Escalate every unusual-geo alert to keep false-negative risk at zero",
                    "Close after noting VPN use is common for marketing staff",
                    "Escalate for reset/session kill if suspicious success; else document FP pattern",
                ],
                "answer_idx": 2,
                "example": "Suspicious success without MFA/VPN justification → escalate for reset and session revoke. Clear VPN/travel story → document and close.",
            },
            "change_mind": {
                "teach": "Approved travel, corporate VPN exit, or failed-only attempts.",
                "choices": [
                    "Only if the source country appears on a threat-intel blocklist",
                    "Documented travel/VPN or failed-only attempts without follow-on abuse",
                    "Keep it escalated once fired — geo alerts should not be closed",
                ],
                "answer_idx": 1,
                "example": "Approved travel, known VPN exit, or no successful auth would move me toward close with notes.",
            },
        },
        "model": {
            "validate": "Confirm success/fail, MFA, and geo quality.",
            "context": "Baseline jsmith locations/hours/VPN.",
            "analyze": "Impossible travel vs VPN; concurrent sessions.",
            "correlate": "Identity changes + mailbox rules + downloads.",
            "decide": "Suspicious success → escalate containment; else document.",
            "change_mind": "Travel ticket, VPN exit evidence, or failed-only login.",
        },
    },
    {
        "id": "edr_powershell",
        "order": 3,
        "title": "EDR malware + encoded PowerShell",
        "tag": "Endpoint",
        "difficulty": 2,
        "prompt": (
            "EDR flags malware on a sales laptop — a suspicious file in Downloads spawned "
            "PowerShell with an encoded command. Walk me through it."
        ),
        "why_hm": "Tests process-tree thinking and when to isolate.",
        "guided": {
            "validate": {
                "teach": "Pull detection name, severity, MITRE tags, host, user, timestamp.",
                "choices": [
                    "Open full alert + host/user + process details before acting",
                    "Isolate the host from the severity badge alone before opening details",
                    "Ask the user to reboot and re-run the scan before reviewing the alert",
                ],
                "answer_idx": 0,
                "example": "I'd open the full EDR alert — detection name, host, user, and process details — before containment.",
            },
            "context": {
                "teach": "Is this a developer box? Sales? Do they run scripts? Criticality of the host.",
                "choices": [
                    "Treat a Downloads path as enough proof of user-driven malware",
                    "Host role + user role + whether encoded PS is expected",
                    "Skip role checks — treat every laptop endpoint at the same severity",
                ],
                "answer_idx": 1,
                "example": "I'd check whether this is a sales endpoint where encoded PowerShell is unusual versus a build machine.",
            },
            "analyze": {
                "teach": "Process tree, parent process, decode command, hash reputation.",
                "choices": [
                    "Decide from the file path string without decoding the command",
                    "Treat the EDR signature name as sufficient analysis",
                    "Process tree + decode command + hash intel",
                ],
                "answer_idx": 2,
                "example": "I'd inspect the process tree, decode the PowerShell, and hash-check the executable.",
            },
            "correlate": {
                "teach": "How did file arrive? Persistence? Lateral movement?",
                "choices": [
                    "Quarantine the file in EDR and close once the process is killed",
                    "Delivery path + persistence + outbound/lateral activity",
                    "Stop after confirming that one PowerShell process has exited",
                ],
                "answer_idx": 1,
                "example": "I'd check email/browser delivery, persistence (tasks/run keys), and any lateral or C2 activity.",
            },
            "decide": {
                "teach": "Confirmed malicious + callbacks/persistence → isolate + escalate. Known tool FP → document + tune.",
                "choices": [
                    "Isolate/escalate if malicious behaviour confirmed; else document FP",
                    "Leave the host online longer to collect more telemetry before containment",
                    "Recommend full reimage for any encoded PowerShell detection",
                ],
                "answer_idx": 0,
                "example": "Malicious execution with network/persistence → recommend isolation and escalate with timeline. Known-good tool → document and suggest tuning.",
            },
            "change_mind": {
                "teach": "Known admin tool, signed binary, ticketed IT activity.",
                "choices": [
                    "Downgrade only if the user is a VIP who needs the laptop today",
                    "Keep the escalate decision once EDR labeled it malware",
                    "Proof it's a signed/approved IT or security tool with a ticket",
                ],
                "answer_idx": 2,
                "example": "A change ticket showing approved security tooling or a signed known-good binary would move me toward close/tune.",
            },
        },
        "model": {
            "validate": "Confirm EDR alert fields and host identity.",
            "context": "Sales laptop — encoded PS is unusual.",
            "analyze": "Tree, decode, hash/reputation.",
            "correlate": "Delivery, persistence, lateral/C2.",
            "decide": "Malicious → isolate + escalate with evidence pack.",
            "change_mind": "Approved tool / signed binary / IT change record.",
        },
    },
    {
        "id": "lateral_rdp",
        "order": 4,
        "title": "Lateral movement (RDP)",
        "tag": "Network",
        "difficulty": 2,
        "prompt": (
            "Alert: unusual RDP from a contractor workstation to three internal servers, "
            "including a file server. The contractor account was flagged yesterday. What now?"
        ),
        "why_hm": "Tests scoping, urgency, and escalation humility mid-incident.",
        "guided": {
            "validate": {
                "teach": "Confirm RDP successes, accounts used, destinations, timestamps.",
                "choices": [
                    "Close as expected remote support because contractors often use RDP",
                    "Confirm which RDP sessions succeeded and with which account",
                    "Start with the contractor's HR status instead of session success logs",
                ],
                "answer_idx": 1,
                "example": "I'd confirm successful RDP sessions, source host, destinations, and account used.",
            },
            "context": {
                "teach": "Yesterday's flag matters — this may already be mid-incident.",
                "choices": [
                    "Pull yesterday's flag + whether contractor should RDP to servers",
                    "Treat yesterday's flag as unrelated and investigate this RDP alert alone",
                    "Message the contractor on Teams for context before pulling prior flags",
                ],
                "answer_idx": 0,
                "example": "I'd review yesterday's flag and whether this contractor is authorized to RDP to those servers.",
            },
            "analyze": {
                "teach": "Blast radius: three servers including file server is serious.",
                "choices": [
                    "Treat internal RDP as low priority unless the source is external",
                    "Prioritize the SIEM rule severity label over which servers were reached",
                    "Treat as potential lateral movement with priority on file server access",
                ],
                "answer_idx": 2,
                "example": "Multiple internal RDP hops including a file server after a prior flag looks like lateral movement, not noise.",
            },
            "correlate": {
                "teach": "Auth on targets, file access, further hops, DC logons.",
                "choices": [
                    "Scope auth/file access on targets and any further movement",
                    "Limit scope to the first successful RDP event to move faster",
                    "Recommend reimaging all three servers before collecting auth evidence",
                ],
                "answer_idx": 0,
                "example": "I'd scope successful auths and file access on the targets and search for further movement or DC logons.",
            },
            "decide": {
                "teach": "Escalate to IR/Tier-2; disable account; isolate if policy allows; preserve evidence.",
                "choices": [
                    "Monitor quietly for more hops before involving Tier-2",
                    "Escalate now with timeline; recommend account disable + isolation per policy",
                    "Close as normal contractor remote work since the account exists",
                ],
                "answer_idx": 1,
                "example": "I'd escalate immediately with a UTC timeline and recommend disabling the account and isolating affected hosts per policy while preserving evidence.",
            },
            "change_mind": {
                "teach": "Documented jump-host procedure / approved remote support ticket.",
                "choices": [
                    "Accept the contractor's verbal assurance that the access was needed",
                    "Default to wipe-and-rebuild even if authorization evidence appears",
                    "Valid change/support ticket proving authorized RDP path",
                ],
                "answer_idx": 2,
                "example": "A valid remote-support ticket and approved jump-host path would make me reconsider malicious lateral movement.",
            },
        },
        "model": {
            "validate": "Confirm RDP success details.",
            "context": "Prior flag + contractor privileges.",
            "analyze": "Multi-hop to file server = high concern.",
            "correlate": "Scope targets + further movement.",
            "decide": "Escalate + contain account/hosts; preserve evidence.",
            "change_mind": "Authorized remote-support ticket/path.",
        },
    },
    {
        "id": "exfil_dlp",
        "order": 5,
        "title": "Data exfiltration / DLP",
        "tag": "DLP",
        "difficulty": 2,
        "prompt": (
            "DLP alerts that a user uploaded 2.3 GB to personal cloud storage outside business hours. "
            "Walk me through your investigation."
        ),
        "why_hm": "Tests data sensitivity judgment and HR/legal awareness.",
        "guided": {
            "validate": {
                "teach": "Confirm user, volume, destination, file types, timestamp.",
                "choices": [
                    "Close as personal backup because cloud sync is common after hours",
                    "Notify management of theft before confirming what data left",
                    "Validate volume, destination, labels, and exact time",
                ],
                "answer_idx": 2,
                "example": "I'd confirm the user, byte volume, destination app, file types/labels, and timestamp.",
            },
            "context": {
                "teach": "Does their role handle that data? Approved migration?",
                "choices": [
                    "Judge risk mainly from the 2.3 GB volume figure",
                    "Role + data sensitivity + any approved migration",
                    "Treat after-hours uploads as acceptable for anyone with cloud access",
                ],
                "answer_idx": 1,
                "example": "I'd check whether their role handles that data and if there's an approved cloud migration.",
            },
            "analyze": {
                "teach": "2.3 GB off-hours to personal cloud is significant.",
                "choices": [
                    "Treat large off-hours personal-cloud upload as high priority until cleared",
                    "Defer DLP until an endpoint malware alert confirms hostile intent",
                    "Deprioritize because DLP often fires on non-malware activity",
                ],
                "answer_idx": 0,
                "example": "Large off-hours upload to personal cloud is suspicious until business justification is proven.",
            },
            "correlate": {
                "teach": "Staging, archives, unusual access, other alerts on the user/host.",
                "choices": [
                    "Isolate the laptop first to stop further uploads, then review logs",
                    "Look for staging/compression and related endpoint/identity alerts",
                    "Rely only on the single DLP alert row for the investigation",
                ],
                "answer_idx": 1,
                "example": "I'd look for local staging/zip activity and related endpoint or identity alerts for that user.",
            },
            "decide": {
                "teach": "Sensitive data + no justification → escalate (IR/HR/legal as policy). Else document.",
                "choices": [
                    "Message the user on Slack asking why they uploaded the files",
                    "Close once the upload session ends and no more DLP fires",
                    "Escalate if sensitive + no justification; preserve evidence",
                ],
                "answer_idx": 2,
                "example": "If sensitive data left without justification, I'd escalate per policy and preserve endpoint evidence — not confront the user solo.",
            },
            "change_mind": {
                "teach": "Manager-approved migration to sanctioned tool; misclassified labels.",
                "choices": [
                    "Approved migration ticket or false DLP classification on benign data",
                    "Never reduce urgency on personal-cloud DLP alerts",
                    "Downgrade automatically if the transfer is under a fixed GB threshold",
                ],
                "answer_idx": 0,
                "example": "A manager-approved migration to an approved service, or proof files weren't sensitive, would change my urgency.",
            },
        },
        "model": {
            "validate": "Confirm DLP details and labels.",
            "context": "Role + approval for off-hours bulk upload.",
            "analyze": "Volume + personal destination + hours = concern.",
            "correlate": "Staging and related alerts.",
            "decide": "Sensitive unexplained exfil → escalate with evidence.",
            "change_mind": "Approved migration or mis-label.",
        },
    },
    {
        "id": "escalate_vs_close",
        "order": 6,
        "title": "Escalate vs close (uncertainty)",
        "tag": "Judgment",
        "difficulty": 1,
        "prompt": (
            "You investigated an alert for 45 minutes and you're still not sure if it's malicious. "
            "The queue has 30 more alerts waiting. What do you do?"
        ),
        "why_hm": "Tests humility, documentation, and queue ethics — huge HM favourite.",
        "guided": {
            "validate": {
                "teach": "Uncertainty after earnest effort is an evidence gap, not failure.",
                "choices": [
                    "Recognize you have an evidence/confidence gap after due diligence",
                    "Call it malicious on gut feel so the ticket can leave your queue",
                    "Mark benign to protect queue SLA since nothing definitive showed up",
                ],
                "answer_idx": 0,
                "example": "After 45 minutes without a confident call, I treat that as an evidence gap — not something to gamble on.",
            },
            "context": {
                "teach": "Queue pressure is real; missing a true positive costs more than a false escalate.",
                "choices": [
                    "Park the rest of the queue until this one is fully solved",
                    "Close uncertain tickets quickly to keep close-rate metrics healthy",
                    "Prefer safe escalate with notes over silent close under queue pressure",
                ],
                "answer_idx": 2,
                "example": "Queue pressure doesn't justify closing something I can't classify — false escalate beats missed incident.",
            },
            "analyze": {
                "teach": "Write what you know vs don't know.",
                "choices": [
                    "Escalate with a one-line 'needs review' and no investigation detail",
                    "List checked items, findings, unknowns, and hypothesis",
                    "Dismiss the alert so it doesn't block the next 30 in queue",
                ],
                "answer_idx": 1,
                "example": "I'd write what I checked, what I found, what I couldn't determine, and my best hypothesis.",
            },
            "correlate": {
                "teach": "Attach indicators/timestamps you already collected.",
                "choices": [
                    "Give Tier-2 a verbal Slack summary without attaching artifacts",
                    "Escalate the alert ID only and let Tier-2 rebuild the timeline",
                    "Attach key logs/IOCs/timestamps so Tier-2 doesn't restart from zero",
                ],
                "answer_idx": 2,
                "example": "I'd attach timestamps, log excerpts, and indicators so the next analyst starts from my work.",
            },
            "decide": {
                "teach": "Escalate. Notify lead if queue coverage needed.",
                "choices": [
                    "Escalate with urgency tag + tell lead you need queue coverage",
                    "Hold the ticket overnight and resume when the queue is quieter",
                    "Close as inconclusive so it doesn't inflate escalate metrics",
                ],
                "answer_idx": 0,
                "example": "I'd escalate with a clear urgency based on what I do know, and flag the lead that the queue needs coverage.",
            },
            "change_mind": {
                "teach": "If a teammate finds a clear FP explanation in your notes, they can close — that's fine.",
                "choices": [
                    "Avoid escalating uncertain cases to protect your accuracy score",
                    "Clear FP evidence found by next analyst can close it — that's success",
                    "Once escalated, insist it stay open even if Tier-2 proves FP",
                ],
                "answer_idx": 1,
                "example": "If Tier-2 finds a clear false-positive explanation, closing it is fine — my job was not to gamble.",
            },
        },
        "model": {
            "validate": "Confidence gap after due diligence.",
            "context": "Cost of miss > cost of escalate.",
            "analyze": "Document knowns/unknowns/hypothesis.",
            "correlate": "Hand off evidence pack.",
            "decide": "Escalate + communicate queue impact.",
            "change_mind": "Clear FP proof later is OK.",
        },
    },
    {
        "id": "password_spray",
        "order": 7,
        "title": "Password spray pattern",
        "tag": "Identity",
        "difficulty": 2,
        "prompt": (
            "You see many failed logons: same password tried across dozens of accounts from one IP "
            "in 10 minutes. No successes yet. Walk me through triage."
        ),
        "why_hm": "Differentiates spray vs brute force — classic SOC screen.",
        "guided": {
            "validate": {
                "teach": "Confirm counts, unique users, one password/IP, time window.",
                "choices": [
                    "Treat it as one noisy account with repeated typos",
                    "Wait to investigate until at least one success appears",
                    "Confirm many users + one password/IP in a short window",
                ],
                "answer_idx": 2,
                "example": "I'd confirm multiple accounts, shared password attempts, single source IP, and the short window.",
            },
            "context": {
                "teach": "Spray = many users, few tries each. Brute = one user, many tries.",
                "choices": [
                    "Defer classification until a successful logon confirms compromise",
                    "Call it spray pattern (many users) vs classic brute (one user)",
                    "Handle all failed-logon bursts with the same brute-force playbook",
                ],
                "answer_idx": 1,
                "example": "Many users with few attempts each from one IP is password spray, not single-account brute force.",
            },
            "analyze": {
                "teach": "Even without success, this is hostile recon/attack in progress.",
                "choices": [
                    "Treat as active attack — contain source even without 4624 yet",
                    "Monitor until a 4624 appears before recommending containment",
                    "Email targeted users to change passwords and pause technical response",
                ],
                "answer_idx": 0,
                "example": "I'd treat it as an active spray even without successes and move to contain the source IP.",
            },
            "correlate": {
                "teach": "Any 4624 successes from that IP? Other apps? VPN?",
                "choices": [
                    "Force a global password reset for all accounts immediately",
                    "Stay focused on the failed (4625) events only",
                    "Hunt successes from that IP across auth sources",
                ],
                "answer_idx": 2,
                "example": "I'd search for any successful logons from that IP across related auth logs.",
            },
            "decide": {
                "teach": "Block/rate-limit IP per policy; escalate if successes; document spray.",
                "choices": [
                    "Block/contain source per policy; escalate if any success; ticket the pattern",
                    "Close with a watch note because no account has succeeded yet",
                    "Document as informational noise and leave the source IP unrestricted",
                ],
                "answer_idx": 0,
                "example": "I'd recommend blocking the source per playbook, escalate if any account succeeded, and document the spray.",
            },
            "change_mind": {
                "teach": "Legit pen-test / approved red team with ticket.",
                "choices": [
                    "Close if the failures pause for a few minutes",
                    "Valid red-team/pen-test authorization covering that IP/window",
                    "Never reclassify once you've recommended containing the IP",
                ],
                "answer_idx": 1,
                "example": "An approved pen-test window covering that source would reframe it as expected testing.",
            },
        },
        "model": {
            "validate": "Confirm spray shape in the data.",
            "context": "Spray vs brute definition.",
            "analyze": "Active attack without needing success first.",
            "correlate": "Hunt 4624/success from source.",
            "decide": "Contain IP; escalate on success; document.",
            "change_mind": "Authorized testing ticket.",
        },
    },
    {
        "id": "powershell_fp",
        "order": 8,
        "title": "PowerShell alert on a developer box",
        "tag": "Endpoint",
        "difficulty": 2,
        "prompt": (
            "Detection: PowerShell with Base64-encoded command on a developer's workstation. "
            "Walk me through triage."
        ),
        "why_hm": "Tests FP discipline — developers run PS; attackers do too.",
        "guided": {
            "validate": {
                "teach": "Don't panic; don't dismiss. Get command line + parent process.",
                "choices": [
                    "Close quickly because developers routinely run encoded PowerShell",
                    "Pull full command line + parent process before verdict",
                    "Isolate on any Base64 PowerShell detection before reviewing details",
                ],
                "answer_idx": 1,
                "example": "I'd pull the full command line and parent process before deciding malicious vs expected.",
            },
            "context": {
                "teach": "Devs run scripts; parent process matters (IDE vs Office).",
                "choices": [
                    "Consider role + whether parent is IDE/build vs Office/script host abuse",
                    "Clear the alert from developer role without checking the parent process",
                    "Treat any Base64-encoded command as malware regardless of context",
                ],
                "answer_idx": 0,
                "example": "On a developer host I'd expect some scripting, but parent process still matters — IDE vs WinWord is different.",
            },
            "analyze": {
                "teach": "Decode Base64; look for download cradles, cred access, C2.",
                "choices": [
                    "Recommend isolation solely because the command was Base64-encoded",
                    "Skip decoding and rely on detection name plus host role",
                    "Decode payload and look for download/cred/C2 behaviour",
                ],
                "answer_idx": 2,
                "example": "I'd decode the Base64 and look for download cradles, credential access, or C2 patterns.",
            },
            "correlate": {
                "teach": "Follow-on files, odd outbound, persistence.",
                "choices": [
                    "Confirm with the developer first and close if they say it was them",
                    "Check follow-on file writes, odd egress, persistence",
                    "End the investigation once the decode looks like a build helper",
                ],
                "answer_idx": 1,
                "example": "I'd correlate temp file writes, unusual outbound connections, and persistence in the same session.",
            },
            "decide": {
                "teach": "Known build script → close + tune note. Malicious patterns → escalate.",
                "choices": [
                    "Escalate every encoded PowerShell hit to stay safe",
                    "Close all PowerShell alerts on developer workstations by default",
                    "Close/tune if known-good build; escalate if malicious behaviour",
                ],
                "answer_idx": 2,
                "example": "Known build/admin script → document and close with tuning note. Malicious decode/behaviour → escalate.",
            },
            "change_mind": {
                "teach": "New network callback or persistence after you almost closed.",
                "choices": [
                    "New C2/persistence evidence after initial review",
                    "Leave a closed FP closed even if new network callbacks appear",
                    "Reopen only if a manager explicitly asks you to re-check",
                ],
                "answer_idx": 0,
                "example": "If follow-on activity showed a callback or persistence, I'd reopen and escalate.",
            },
        },
        "model": {
            "validate": "Command line + parent process first.",
            "context": "Developer baseline vs Office-spawned PS.",
            "analyze": "Decode; hunt malicious patterns.",
            "correlate": "Follow-on host/network activity.",
            "decide": "Known-good → close/tune; bad → escalate.",
            "change_mind": "Callback/persistence after the fact.",
        },
    },
]


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    """Return one scenario by id."""
    for s in SCENARIOS:
        if s["id"] == scenario_id:
            return s
    return None


def public_scenario_list() -> list[dict[str, Any]]:
    """Hub cards — no answers."""
    return [
        {
            "id": s["id"],
            "order": s["order"],
            "title": s["title"],
            "tag": s["tag"],
            "difficulty": s["difficulty"],
            "prompt": s["prompt"],
            "why_hm": s["why_hm"],
        }
        for s in SCENARIOS
    ]


def guided_payload(scenario_id: str) -> dict[str, Any] | None:
    """Client payload for Guided mode (includes choices; not the raw answer key alone)."""
    s = get_scenario(scenario_id)
    if not s:
        return None
    steps_out = []
    for step in STEPS:
        sid = step["id"]
        g = s["guided"][sid]
        steps_out.append({
            **step,
            "teach": g["teach"],
            "choices": g["choices"],
            "answer_idx": g["answer_idx"],
            "example": g["example"],
        })
    return {
        "id": s["id"],
        "title": s["title"],
        "tag": s["tag"],
        "prompt": s["prompt"],
        "why_hm": s["why_hm"],
        "mode": "guided",
        "steps": steps_out,
    }


def coached_payload(scenario_id: str) -> dict[str, Any] | None:
    """Client payload for Coached — prompts only; model answers returned after submit."""
    s = get_scenario(scenario_id)
    if not s:
        return None
    return {
        "id": s["id"],
        "title": s["title"],
        "tag": s["tag"],
        "prompt": s["prompt"],
        "why_hm": s["why_hm"],
        "mode": "coached",
        "steps": [
            {
                **step,
                "hint": s["guided"][step["id"]]["teach"],
            }
            for step in STEPS
        ],
    }


def live_payload(scenario_id: str) -> dict[str, Any] | None:
    """Client payload for Live — no hints."""
    s = get_scenario(scenario_id)
    if not s:
        return None
    return {
        "id": s["id"],
        "title": s["title"],
        "tag": s["tag"],
        "prompt": s["prompt"],
        "mode": "live",
        "seconds": LIVE_SECONDS,
        "steps": list(STEPS),
    }


def model_answers(scenario_id: str) -> dict[str, str]:
    """Model step answers for reveal / grading context."""
    s = get_scenario(scenario_id)
    if not s:
        return {}
    return dict(s.get("model") or {})


def grade_guided_choice(scenario_id: str, step_id: str, choice_idx: int) -> dict[str, Any]:
    """Grade one Guided multiple-choice step."""
    s = get_scenario(scenario_id)
    if not s or step_id not in s["guided"]:
        return {"ok": False, "error": "Unknown step"}
    g = s["guided"][step_id]
    correct = int(choice_idx) == int(g["answer_idx"])
    return {
        "ok": True,
        "correct": correct,
        "answer_idx": g["answer_idx"],
        "example": g["example"],
        "teach": g["teach"],
    }


def build_live_rubric_prompt(scenario: dict[str, Any], answers: dict[str, str]) -> str:
    """Prompt for Ollama to score a Live walkthrough (beginner-friendly coach)."""
    model = scenario.get("model") or {}
    parts = [
        "You are a patient SOC interview coach for a beginner who has never worked in a SOC.",
        "Score their timed walkthrough. Be encouraging but honest.",
        "Respond ONLY with JSON:",
        '{"score":0-100,"verdict":"short praise or main gap","tips":["tip1","tip2","tip3"]}',
        "",
        f"Scenario: {scenario['prompt']}",
        "",
        "Ideal points:",
    ]
    for step in STEPS:
        parts.append(f"- {step['id']}: {model.get(step['id'], '')}")
    parts.append("")
    parts.append("Candidate answers:")
    for step in STEPS:
        sid = step["id"]
        parts.append(f"- {sid}: {(answers.get(sid) or '').strip() or '(blank)'}")
    return "\n".join(parts)
