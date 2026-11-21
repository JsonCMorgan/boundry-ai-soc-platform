"""
Generate secplus_lessons.py — Phase 1 micro-lesson spine (~52 lessons).
Run: python tools/gen_secplus_phase1.py
"""
from __future__ import annotations

import pprint
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "secplus_lessons.py"

# Domain meta (official SY0-701 weights)
DOMAINS = [
    {"id": "d1_concepts", "order": 1, "weight": 12, "title": "General Security Concepts",
     "short": "CIA, controls, change, crypto", "color": "#2dd4bf",
     "goal": "Name control types and CIA/AAA the way a SOC ticket expects."},
    {"id": "d2_threats", "order": 2, "weight": 22, "title": "Threats, Vulnerabilities, and Mitigations",
     "short": "Actors, vectors, vulns, IOCs", "color": "#ff8c00",
     "goal": "Separate spray vs brute vs BEC vs malware — then pick the right mitigation."},
    {"id": "d3_architecture", "order": 3, "weight": 18, "title": "Security Architecture",
     "short": "ZT, infra, data, resilience", "color": "#a78bfa",
     "goal": "Pick architecture moves that remove exposure, not just dashboards."},
    {"id": "d4_operations", "order": 4, "weight": 28, "title": "Security Operations",
     "short": "Hunt, IR, IAM, SOAR, sources", "color": "#00ff88",
     "goal": "Run the shift: alert → source → contain → ticket — Boundry ops."},
    {"id": "d5_oversight", "order": 5, "weight": 20, "title": "Security Program Management and Oversight",
     "short": "Gov, risk, vendors, awareness", "color": "#f472b6",
     "goal": "Close the loop after IR: owner, risk treatment, vendor, awareness."},
]

JOB = {
    "d1": [
        {"label": "Glossary", "href": "/glossary", "why": "Lock CIA / AAA / control-type terms."},
        {"label": "Interview Gym", "href": "/career/interview", "why": "Say control types on a case."},
    ],
    "d2": [
        {"label": "Interview Gym", "href": "/career/interview", "why": "Brief spray vs BEC vs malware."},
        {"label": "Shift Sim", "href": "/career/shift", "why": "Grade live alert patterns."},
    ],
    "d3": [
        {"label": "Interview Gym", "href": "/career/interview", "why": "Architecture fixes for RDP / CA."},
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Write the control that should have existed."},
    ],
    "d4": [
        {"label": "Shift Sim", "href": "/career/shift", "why": "Practice the queue."},
        {"label": "SPL Learn", "href": "/career/spl", "why": "Hunt identity failures."},
        {"label": "KQL Learn", "href": "/career/kql", "why": "Sentinel SigninLogs path."},
        {"label": "SOAR Lab", "href": "/soar", "why": "Automation with a human gate."},
    ],
    "d5": [
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Document residual risk + next."},
        {"label": "Interview Gym", "href": "/career/interview", "why": "Program talk after IR."},
    ],
}


def _wrap(s: str) -> str:
    return textwrap.dedent(s).strip()


# Each tuple: (id, domain, obj, title, minutes, terms, sections[(h,b)], practice, quiz, pbq|None)
# practice/quiz items: (prompt/q, [4 choices], answer_idx, hint, explain)
# pbq: dict or None

def _mc(prompt, choices, idx, hint, explain):
    return {
        "prompt": prompt, "choices": choices, "answer_idx": idx,
        "hint": hint, "explain": explain,
    }


def _qz(qid, q, choices, idx, explain):
    return {"id": qid, "q": q, "choices": choices, "answer_idx": idx, "explain": explain}


LESSON_SPECS: list[dict] = []


def add(lesson_id, domain_id, objective_ref, title, minutes, key_terms, sections,
        practice, quiz, pbq=None, goal=""):
    LESSON_SPECS.append({
        "id": lesson_id,
        "domain_id": domain_id,
        "objective_ref": objective_ref,
        "title": title,
        "minutes": minutes,
        "key_terms": key_terms,
        "sections": [{"heading": h, "body": _wrap(b)} for h, b in sections],
        "practice": practice,
        "quiz": quiz,
        "pbq": pbq,
        "goal": goal or f"Master {objective_ref} in Boundry SOC language.",
    })


# ═══════════════════════════════════════════════════════════════════════════
# D1 — 6 lessons (no PBQ — vocab/governance)
# ═══════════════════════════════════════════════════════════════════════════

add(
    "sp_d1_01_control_functions", "d1_concepts", "1.1",
    "Control functions that hire managers use", 10,
    ["Preventive Control", "Detective Control", "Corrective Control", "Directive Control"],
    [
        ("Two axes — do not mash them", """
            Security+ Domain 1 starts with vocabulary you already use in Boundry tickets.

            Function (what the control does):
              Preventive  — stops the event (firewall DENY 3389 to PROD-DC01)
              Detective   — tells you it happened (SIEM Failed Logon Burst)
              Corrective  — reduces impact after (isolate WS-HR-03, reset hash)
              Deterrent   — raises attacker cost (banner, cameras)
              Compensating — extra control when the preferred one is missing
              Directive   — tells people what to do (AUP, change ticket CHG-512)

            Interview sentence: 'I classify the control first — preventive, detective,
            or corrective — then I decide whether the alert is the control working
            or the control missing.'
            """),
        ("Boundry map", """
            Encoded PowerShell from Invoice.xlsm → detective (EDR) then corrective (isolate).
            Internet RDP ALLOW to PROD-DC01 → preventive control FAILED; fix the rule.
            Quarterly vuln scan from JUMP-01 with CHG-512 → directive (the ticket) plus
            operational process (the scan window).
            """),
    ],
    [
        _mc(
            "Boundry SIEM rule 'Failed Logon Burst' fires on 12 failures in 60 seconds. Which control function is the SIEM rule itself?",
            ["Preventive — it blocked the source IP before the 12th failure",
             "Detective — it notified you that the burst occurred",
             "Corrective — it reset every user's password automatically",
             "Physical — it locked the server room door"],
            1, "The rule watches and alerts. Blocking would be a different control.",
            "SIEM correlation is detective. Preventive would be lockout/MFA/firewall; corrective is the reset or isolate after.",
        ),
        _mc(
            "Firewall DENY inbound tcp/3389 to PROD-DC01 from the internet is primarily:",
            ["Detective", "Preventive", "Directive", "Compensating for missing CCTV"],
            1, "Deny stops the session before it starts.",
            "A deny rule prevents the RDP session. Logging the deny would add a detective layer.",
        ),
        _mc(
            "Isolating WS-HR-03 after excel.exe → powershell.exe -enc is:",
            ["Preventive only", "Directive only", "Corrective — reduces impact after execution", "A deterrent banner"],
            2, "The host already ran code; you are limiting blast radius.",
            "Isolation is corrective. Preventive would have been ASR/mail macro block before execution.",
        ),
    ],
    [
        _qz("q_d1_01a", "Which control function is a SIEM correlation alert?",
            ["Preventive", "Detective", "Physical cage lock", "Compensating VPN only"], 1,
            "Alerts notify. They do not by themselves stop the first event."),
        _qz("q_d1_01b", "CHANGE ticket CHG-512 authorizing a scanner is best called:",
            ["Detective SIEM", "Directive / governance artefact", "Corrective isolate", "Encryption"], 1,
            "Tickets tell people what is allowed and when."),
        _qz("q_d1_01c", "Opening inbound 3389 'just for the vendor' with no compensating control means:",
            ["Preventive control is working", "A preventive network control is missing or failed",
             "Only a deterrent failed", "CIA confidentiality is automatically fine"], 1,
            "ALLOW from the internet removes the preventive path control."),
        _qz("q_d1_01d", "Best interview framing after a spray alert?",
            ["Skip control language", "Name whether you are looking at detective signal vs missing preventive",
             "Only discuss CCTV", "Call every alert corrective"], 1,
            "Hiring managers want control vocabulary tied to the ticket."),
    ],
)

add(
    "sp_d1_02_control_implementation", "d1_concepts", "1.1",
    "Technical, managerial, operational, physical", 9,
    ["Technical Control", "Managerial Control", "Operational Control", "Physical Control"],
    [
        ("Implementation axis", """
            Function answers 'what job'. Implementation answers 'how it is built'.

              Technical  — firewall, EDR, MFA, DLP rule
              Managerial — risk assessment, policy, vendor review
              Operational — SOC shift, awareness briefing, backup restore test
              Physical   — badge door, cage, CCTV

            Same incident can touch more than one. Example: BEC response uses technical
            (revoke sessions) + operational (finance callback) + managerial (exception for
            legacy auth with an owner and date).
            """),
        ("Near-miss to avoid", """
            Do not call MFA 'physical' because a phone is involved. MFA is technical
            (and sometimes operational process around travel). Physical is doors and cages.

            Compensating control example: temporary jump-host allow-list while VPN is broken —
            documented, owned, time-boxed. Hallway 'just leave 3389 open' is not compensating.
            """),
    ],
    [
        _mc(
            "EDR isolating a host is which implementation type?",
            ["Managerial policy only", "Technical", "Physical badge", "AUP reprint"],
            1, "Software enforcing containment.",
            "EDR actions are technical controls. The IR playbook around them is operational.",
        ),
        _mc(
            "A written risk acceptance for kill switch OFF with owner and review date is:",
            ["Technical firewall rule", "Managerial / governance artefact", "Physical CCTV", "Base64 encoding"],
            1, "Ownership and acceptance live in the program, not in a packet filter.",
            "Documented acceptance is managerial. Turning the kill switch ON would be technical mitigation.",
        ),
        _mc(
            "Badge reader on the server cage is:",
            ["Technical SIEM", "Physical", "Detective only by definition", "Directive CHG ticket"],
            1, "Doors and cages.",
            "Physical controls protect the hardware plane your SIEM cannot see."),
    ],
    [
        _qz("q_d1_02a", "MFA enforced in Entra is primarily:",
            ["Physical", "Technical", "Only managerial", "Deterrent poster"], 1,
            "Identity platform enforcement is technical."),
        _qz("q_d1_02b", "SOC shift handoff checklist is:",
            ["Physical", "Operational", "Encryption", "Compensating RDP"], 1,
            "People process on a cadence = operational."),
        _qz("q_d1_02c", "Vendor security questionnaire before buying a mail filter is:",
            ["Managerial / third-party review", "Physical", "Corrective isolate", "Hashing"], 0,
            "Due diligence before trust is managerial."),
        _qz("q_d1_02d", "Why separate function vs implementation in an interview?",
            ["To sound random", "So you can say 'detective technical' without mixing axes",
             "Because CompTIA forbids both", "Only physical matters"], 1,
            "Clear axes show you can classify controls under pressure."),
    ],
)

add(
    "sp_d1_03_cia_fundamentals", "d1_concepts", "1.2",
    "CIA triad in ticket language", 10,
    ["Confidentiality", "Integrity", "Availability", "Non-repudiation"],
    [
        ("Say the impact, not the slogan", """
            CIA triad (Boundry versions):
              Confidentiality — inbox rule forwarding CFO mail to Gmail (BEC) breaks this
              Integrity      — attacker-created local admin svc_backup2 overnight
              Availability   — spray lockouts that also hit a legit password change

            Non-repudiation: you can prove who did it. Signed mail, privileged-account
            logging, and a ticket that names the analyst who isolated the host.

            Deception (honeypot / honeytoken) is usually detective — high-confidence alert,
            not your first SMB control.
            """),
        ("Physical leftover still counts", """
            A stolen laptop with no disk encryption is a confidentiality failure even if
            your SIEM is perfect. BitLocker / FileVault is how Domain 1 meets Domain 3/4.

            Interview trap: do not call every outage 'integrity'. Wrong data is integrity;
            systems down is availability.
            """),
    ],
    [
        _mc(
            "CFO mailbox forward-all to personal Gmail primarily breaks:",
            ["Availability of the printer", "Confidentiality of mail contents",
             "Integrity of the firewall rulebase only", "Physical cage locks"],
            1, "Secrets leaving to a personal inbox.",
            "External forward of finance mail is a confidentiality failure (collection)."),
        _mc(
            "New local admin svc_backup2 with no change ticket primarily threatens:",
            ["Integrity of privilege boundaries (and likely more)", "Only printer availability",
             "Only CCTV", "Hashing algorithms"],
            0, "Unauthorized privileged account = trust boundary broken.",
            "Unexpected privilege is an integrity (and often confidentiality) problem."),
        _mc(
            "Spray lockouts blocking a legit password change hit which CIA pillar hardest for users?",
            ["Confidentiality of CCTV", "Availability of accounts", "Non-repudiation posters", "Physical only"],
            1, "Users cannot authenticate / work.",
            "Lockouts are an availability impact even when the detective control was right to fire."),
    ],
    [
        _qz("q_d1_03a", "Invoice.xlsm ransomware that encrypts shares primarily hits:",
            ["Availability (and integrity of data)", "Only physical doors", "Only AUP text", "Directive CHG"], 0,
            "Encrypted files are unavailable; integrity of originals is also gone."),
        _qz("q_d1_03b", "Ticket naming who isolated the host supports:",
            ["Non-repudiation / accountability", "Opening more RDP", "Deleting logs", "Legacy auth"], 0,
            "Named actions in tickets create an audit trail."),
        _qz("q_d1_03c", "Honeytoken mailbox alert is best described as:",
            ["Preventive encryption", "Detective deception", "Physical badge", "RTO metric"], 1,
            "Deception triggers high-confidence detection."),
        _qz("q_d1_03d", "Unencrypted stolen CEO laptop is mainly:",
            ["Confidentiality failure", "Only availability of MFA", "Directive scan", "SOAR playbook"], 0,
            "Disk encryption is the confidentiality control for lost devices."),
    ],
)

add(
    "sp_d1_04_aaa_zero_trust", "d1_concepts", "1.2",
    "AAA, Zero Trust, gap analysis", 11,
    ["Authentication", "Authorization", "Accounting", "Zero Trust", "Gap Analysis"],
    [
        ("AAA on a travel login", """
            AAA:
              Identification  — username / UPN
              Authentication  — password, MFA, cert, Windows Hello
              Authorization   — group, role, Conditional Access grant
              Accounting      — 4624/4625, SigninLogs, SIEM, ticket notes

            CEO sign-in from Frankfurt, MFA passed, HR confirms conference:
              authn = MFA + password path
              authz = CA allowed the session
              accounting = SigninLogs / SIEM row you paste into the ticket

            Interview trap: do not call MFA 'identification'. MFA is authentication.
            """),
        ("Zero Trust + gap analysis (ops version)", """
            Never trust the network location. Authenticate and authorize every session.
            Travel login is not 'trusted' because of corporate VPN — it is trusted because
            MFA passed AND HR confirmed travel.

            Exposed RDP to a DC is the opposite of Zero Trust.

            Gap analysis: compare required control vs what Boundry actually has.
            Example gap: NordVPN kill switch OFF — confidentiality/availability risk if
            the tunnel drops. That is a finding, not a lecture.
            """),
    ],
    [
        _mc(
            "CEO sign-in from Frankfurt, MFA passed, HR confirms. The SIEM/SigninLogs row is:",
            ["Identification only", "Authorization that grants admin",
             "Accounting / audit trail of the authenticated session", "A deterrent flight ban"],
            2, "Logs do not grant access; they record it.",
            "Accounting is the audit trail. MFA was authentication; CA/group was authorization."),
        _mc(
            "Zero Trust ops definition that matches Boundry?",
            ["Trust anyone on VPN with no checks",
             "Authenticate and authorize each session; location alone is not enough",
             "Disable MFA for executives", "Open RDP to speed travel"],
            1, "Session policy, not 'VPN equals trusted'.",
            "ZT is continuous verification. Travel + MFA + process beats network faith."),
        _mc(
            "Kill switch OFF with no owner is a:",
            ["Closed gap", "Gap / untreated risk until mitigated or formally accepted",
             "Proof of encryption", "Directive CHG for Nessus"],
            1, "Required control missing or weak.",
            "Gap analysis names the missing control. Mitigate (ON) or accept with owner/date."),
    ],
    [
        _qz("q_d1_04a", "Password + MFA together are:",
            ["Identification only", "Authentication", "Physical only", "Directive"], 1,
            "Proving who you are = authentication."),
        _qz("q_d1_04b", "Conditional Access grant after MFA is:",
            ["Authorization", "Only accounting", "Hashing", "Deterrent"], 0,
            "Allowing the app/session is authorization."),
        _qz("q_d1_04c", "Trusting 'inside VPN' with no MFA is:",
            ["Strong Zero Trust", "Castle-and-moat thinking, not Zero Trust",
             "Corrective IR", "Non-repudiation"], 1,
            "Network location is not a sufficient trust signal."),
        _qz("q_d1_04d", "Gap analysis compares:",
            ["Required control vs actual control state", "Only font colors on dashboards",
             "RTO to RPO names only", "Base64 to AES always"], 0,
            "Find what should exist versus what does."),
    ],
)

add(
    "sp_d1_05_change_management", "d1_concepts", "1.3",
    "Change management that saves your shift", 10,
    ["Change Management", "Backout Plan", "Allow List", "Stakeholder Notification"],
    [
        ("Why CHG tickets matter", """
            Change management keeps you from paging IR for authorized noise.

            Boundry examples:
              JUMP-01 sequential probes 22/80/443/3389 + ticket CHG-512 'quarterly vuln scan'
                  → false positive if scanner identity matches.
              New local admin svc_backup2 at 03:14, no change ticket
                  → escalate. Absence of change is the signal.
              VPN flap during documented ISP window CHG-441
                  → FP unless kill switch failed.

            Process: request → impact/risk → approval → schedule → implement → verify → backout.
            """),
        ("Ownership and documentation", """
            Stakeholder notification (finance before a mail-filter change).
            Allow-list / deny-list updates belong in the same ticket as the firewall push.
            Ownership: who can approve prod DC firewall changes? Not the helpdesk intern.

            Talk-track: 'I check for a change ticket before I escalate a scan-shaped alert.'

            Documentation is the next analyst's detection logic — your Portfolio What / Why /
            Disposition / MITRE / Next explains why a control exists so nobody 'cleans up'
            the firewall rule that blocks 3389.
            """),
    ],
    [
        _mc(
            "JUMP-01 scans with CHG-512 'quarterly vuln scan'. What is CHG-512 primarily?",
            ["A technical preventive that drops packets",
             "A directive / change-management artefact explaining authorized activity",
             "Proof of nation-state APT", "A cryptographic hash of Nessus"],
            1, "Change tickets explain authorized activity.",
            "Change records keep you from escalating authorized scanner traffic when identity matches."),
        _mc(
            "svc_backup2 local admin at 03:14 with no ticket. Best first read?",
            ["Close as CHG noise", "Escalate — missing change is the signal",
             "Only reboot the DC", "Disable SIEM"],
            1, "No change + privileged account = incident-shaped.",
            "Absence of change management is itself an indicator."),
        _mc(
            "Before disabling legacy auth org-wide you need:",
            ["No plan — just flip it", "Impact check, stakeholders, backout, verify in SigninLogs",
             "Open more RDP", "Delete accounting logs"],
            1, "Change process prevents outages and blind spots.",
            "Verify step: legacy success disappears from SigninLogs after the change."),
    ],
    [
        _qz("q_d1_05a", "Best habit before escalating scan-shaped alerts?",
            ["Ignore all scans", "Check for a matching change ticket / scanner identity",
             "Open 3389", "Disable EDR"], 1,
            "Authorized vuln scans are common FPs when context matches."),
        _qz("q_d1_05b", "Backout plan means:",
            ["Never change prod", "How you reverse the change if verify fails",
             "Only a poster", "Deleting the CHG"], 1,
            "Backout is part of responsible change."),
        _qz("q_d1_05c", "Allow-list update for a scanner IP should live:",
            ["In a sticky note only", "In the same change record as the firewall/SIEM update",
             "Nowhere", "Only in Slack jokes"], 1,
            "Detection and allow-lists need the same audit trail."),
        _qz("q_d1_05d", "Who should approve internet RDP to a DC?",
            ["Random intern DM", "Named owner / CAB with risk acceptance — preferably never approve it",
             "The attacker", "No one ever documents it"], 1,
            "High-risk changes need real ownership — and better architecture."),
    ],
)

add(
    "sp_d1_06_crypto_soc", "d1_concepts", "1.4",
    "Cryptography the SOC actually touches", 11,
    ["Encryption", "Hashing", "Digital Signature", "PKI", "Obfuscation"],
    [
        ("Pick the property", """
            You are not implementing AES in Python on this exam path. You are choosing
            the right property:

              Encryption (confidentiality) — BitLocker; TLS on Boundry; encrypted backups
              Hashing (integrity / stored secrets) — password hashes; file hash for Invoice.xlsm
              Digital signatures / certificates — code signing, HTTPS, S/MIME
              Key stretching / salting — why weak passwords still get sprayed

            Public key vs symmetric: TLS uses both (handshake + session key).
            """),
        ("Obfuscation ≠ encryption + appropriate solutions", """
            Encoded PowerShell (-enc) is NOT encryption. Base64 is obfuscation.
            Say that out loud in Interview Gym.

            Appropriate means: right algorithm, right place, managed keys.
            SOC failures: expired cert, self-signed payment portal, hard-coded API keys,
            legacy NTLM fallback after Kerberos errors (svc_veeam).

            When you paste a hash into a ticket, cryptography is an investigation primitive.
            """),
    ],
    [
        _mc(
            "Attacker used powershell.exe -enc <base64>. What is -enc here?",
            ["Encryption protecting confidentiality", "Obfuscation / encoding — not a confidentiality control",
             "Vendor PKI signature", "bcrypt key stretching"],
            1, "Base64 is reversible without a key.",
            "Encoded command is tradecraft, not cryptography."),
        _mc(
            "Hashing Invoice.xlsm for IOC sharing primarily supports:",
            ["Confidentiality of the file contents", "Integrity / identification of the sample",
             "Opening RDP", "Directive AUP"],
            1, "Hashes identify content; they do not hide it.",
            "File hashes let EDR and mail gateway share an IOC without sending the malware."),
        _mc(
            "BitLocker on the CEO laptop primarily protects:",
            ["Availability of SIEM", "Confidentiality if the device is stolen",
             "Directive CHG text", "SOAR lockout"],
            1, "Lost device + encryption.",
            "Full-disk encryption is the classic confidentiality control for endpoints."),
    ],
    [
        _qz("q_d1_06a", "TLS on the Boundry dashboard mainly provides:",
            ["Physical access", "Confidentiality (and integrity) in transit", "CHG tickets", "Honeypots"], 1,
            "HTTPS protects data in motion."),
        _qz("q_d1_06b", "Base64 PowerShell -enc is:",
            ["Strong encryption", "Obfuscation, not encryption", "A digital signature", "RPO"], 1,
            "Do not call encoding encryption in interviews."),
        _qz("q_d1_06c", "Expired web cert risk includes:",
            ["Only prettier dashboards", "Availability friction + phishing lookalike trust issues",
             "Faster spray", "Better RTO"], 1,
            "Users click through warnings; attackers abuse broken trust cues."),
        _qz("q_d1_06d", "Password hashing without unique salts is weak because:",
            ["Hashes become wallpaper", "Identical passwords share digests; sprays/reuse hurt more",
             "It opens 3389", "It disables MFA"], 1,
            "Salting/stretching are part of 'appropriate' stored-secret crypto."),
    ],
)

print(f"D1 lessons so far: {len(LESSON_SPECS)}")
