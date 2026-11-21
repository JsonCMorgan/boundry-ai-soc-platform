"""D1 lesson specs for Phase 1 builder.

Voice: .cursor/rules/tutor-professor-voice.mdc
Gold standard: sp_d1_01_control_functions (define every term before use).

Depth bar (Option 1): ~15–20 min Show-me. Short work-facing picture OR
"Where you see this at work", then bridge "In Security+ terms, that is X."
Most of the lesson is technical specifics, worked example, how to answer, traps.
"""
from __future__ import annotations


def d1_specs(add, _mc, _qz):
    """Register Domain 1 micro-lessons (6)."""

    add(
        "sp_d1_01_control_functions", "d1_concepts", "1.1",
        "Security controls by the job they do", 18,
        ["Preventive Control", "Detective Control", "Corrective Control", "Directive Control",
         "Security Control", "CompTIA Security+", "Compensating Control", "Deterrent Control"],
        [
            ("Before we start: what this exam is", """
                You are studying for CompTIA Security+. CompTIA is the company that writes
                the certification. Security+ is their entry-level cybersecurity exam. The
                current version of that exam is labeled SY0-701 (say "S-Y-zero-seven-oh-one").
                In these lessons, when I say "the exam," I mean Security+.

                On the exam you will read a short scenario (the question text), then pick
                from several answer choices. Most choices will be wrong. A wrong answer that
                looks almost right is called a distractor. Exam writers use distractors on
                purpose. Your job is to pick the best match for what the question actually says.

                Today we start Domain 1, objective 1.1: security controls. A security control
                is anything that reduces risk. A lock, a firewall rule, a camera, a written
                policy, and a ticket that authorizes a change are all controls.
                """),
            ("Classify a control by the job it does", """
                The exam often asks: what job did this control do? That job is called the
                control's function. Function means "what it does," not "how it was built."
                How it was built (software, policy, people process, or a physical door) is a
                separate idea we cover in the next lesson. If you mix those two ideas, you
                will pick a wrong answer that looks close.

                Where you see this at work: on a SOC desk, a firewall DENY stops a remote
                session before it starts. A SIEM alert tells you twelve failed logons just
                happened. Isolating a laptop after malware already ran shrinks the blast
                radius. A change ticket tells the team the scan is authorized tonight.

                In Security+ terms, that job each control does is the control function:
                preventive, detective, corrective, or directive (plus deterrent and
                compensating when the question uses those words).

                Function list (learn these six):
                  1. Preventive: stops the bad event before it succeeds
                     Example: firewall DENY of remote desktop (TCP 3389) to a domain controller
                  2. Detective: tells you something happened (or is happening)
                     Example: a SIEM alert (SIEM = security log system that raises alerts)
                  3. Corrective: reduces damage after something already happened
                     Example: EDR (endpoint detection and response) isolating a host after
                     PowerShell ran from a malicious Excel file
                  4. Deterrent: raises the cost or fear of attacking
                     Example: login banner, visible cameras, "unauthorized access prohibited"
                  5. Compensating: a planned extra control when the preferred one is missing
                     Example: jump-host + MFA + short time window while you rebuild a
                     broken VPN path, with owner and end date
                  6. Directive: tells people what to do
                     Example: acceptable use policy, change ticket, "no internet RDP" standard

                Technical specifics (desk clues):
                  - Preventive network: DENY/ALLOW on TCP 3389 (RDP), TCP 22 (SSH),
                    TCP 445 (SMB), UDP 500/4500 (IPsec VPN). An ALLOW from the internet
                    to a domain controller means the preventive path control failed or
                    was never there.
                  - Detective identity: Windows 4625 (failed logon), 4624 (success), Entra
                    SigninLogs, SIEM correlation like "Failed Logon Burst."
                  - Detective endpoint: EDR alert on excel.exe → powershell.exe -enc.
                  - Corrective: isolate host, revoke refresh tokens, disable account,
                    restore from known-good backup after ransomware.
                  - Directive: CHG ticket, CAB approval, AUP acknowledgment.
                  - One object can stack functions. A firewall DENY that also logs is
                    preventive first, with a detective log layer on top. The question
                    usually asks for the primary job described.

                Worked example: an HR laptop opens Invoice.xlsm from email. Macros launch
                powershell.exe -enc (Base64-encoded command). EDR alerts. You isolate
                WS-HR-03. Separately, the firewall still shows ALLOW tcp/3389 from the
                internet to PROD-DC01.

                  - EDR alert = detective (it notified you after execution started)
                  - Isolate = corrective (code already ran; you limit spread)
                  - Open 3389 to the DC = missing or failed preventive network control
                  - If a change ticket had authorized a scanner on JUMP-01, that ticket
                    is directive. It does not itself drop packets.

                How to answer on the exam:
                  1. Underline what actually happened: blocked, alerted, cleaned up, or
                     instructed people.
                  2. Ask: what job did THIS control do in the story?
                  3. Separately ask (only if the question asks): how was it built?
                  4. Pick the function that matches what occurred. Do not invent a block
                     that never happened.
                  5. If two controls appear, answer for the one the question names.

                Common trap: calling a SIEM alert "preventive" because you wish it had
                blocked the IP. An alert that only notifies is detective. Another near-miss:
                calling isolate "preventive." Preventive would have blocked the script
                before it ran (ASR rule, macro block, deny list). After execution =
                corrective.

                Remember: preventive stops, detective watches, corrective cleans up,
                directive instructs.
                """),
        ],
        [
            _mc(
                "A Boundry SIEM rule named 'Failed Logon Burst' fires after 12 failures in 60 seconds. "
                "Which control function is the SIEM rule itself? "
                "(SIEM = the log/alert system.)",
                ["Preventive: it blocked the source IP before the 12th failure",
                 "Detective: it notified you that the burst occurred",
                 "Corrective: it reset every user's password automatically",
                 "Physical: it locked the server room door"],
                1, "The rule watches and alerts. Blocking would be a different control.",
                "Correct. The SIEM rule is detective because it notifies you. "
                "Common trap: calling an alert preventive just because you wish it blocked the IP. "
                "Remember: alert = detective.",
            ),
            _mc(
                "A firewall rule that DENY inbound remote desktop (tcp/3389) to PROD-DC01 from the internet is primarily:",
                ["Detective", "Preventive", "Directive", "Compensating for missing CCTV"],
                1, "Deny stops the session before it starts.",
                "Correct. A deny rule prevents the remote desktop session. Logging the deny would add "
                "a detective layer on top. Remember: DENY before the session = preventive.",
            ),
            _mc(
                "Isolating laptop WS-HR-03 after malware already ran is:",
                ["Preventive only", "Directive only", "Corrective: reduces impact after execution", "A deterrent banner"],
                2, "The host already ran code; you are limiting blast radius.",
                "Correct. Isolation is corrective because execution already happened. "
                "Common trap: calling isolate preventive. Preventive would have blocked the "
                "script before it ran. Remember: after execution = corrective.",
            ),
            _mc(
                "A documented jump-host + MFA temporary path while VPN rebuild finishes, with owner and 14-day review, is best called:",
                ["Silent open RDP with no ticket", "Compensating control",
                 "Detective SIEM only", "Deterrent banner only"],
                1, "Planned extra control with owner and time limit.",
                "Correct. Compensating is planned, owned, and temporary when the preferred "
                "control is missing. Common trap: calling undocumented open RDP compensating. "
                "Remember: no owner/date = unmanaged risk, not compensating.",
            ),
        ],
        [
            _qz("q_d1_01a", "Which control function is a SIEM correlation alert?",
                ["Preventive", "Detective", "Physical cage lock", "Compensating VPN only"], 1,
                "Correct. Alerts notify. They do not by themselves stop the first event. "
                "Common trap: any choice that says 'blocked.' Remember: notify = detective."),
            _qz("q_d1_01b", "A change ticket that authorizes a scanner is best called:",
                ["Detective SIEM", "Directive / governance instruction", "Corrective isolate", "Encryption"], 1,
                "Correct. Tickets tell people what is allowed and when. "
                "Common trap: treating a ticket like a packet filter. "
                "Remember: directive = instruction and authorization."),
            _qz("q_d1_01c", "Opening inbound remote desktop 'just for the vendor' with no extra control means:",
                ["Preventive control is working", "A preventive network control is missing or failed",
                 "Only a deterrent failed", "Confidentiality is automatically fine"], 1,
                "Correct. ALLOW from the internet removes the preventive path control. "
                "Remember: open management ports are preventive failures."),
            _qz("q_d1_01d", "Best way to talk about a password-spray alert in an interview?",
                ["Skip control language", "Say whether you are looking at a detective signal vs a missing preventive control",
                 "Only discuss CCTV", "Call every alert corrective"], 1,
                "Correct. Exam and interview both reward: detective signal vs missing preventive. "
                "Common trap: calling every alert corrective. Remember: classify the job first."),
            _qz("q_d1_01e", "Windows event 4625 flooding SIEM with no auto-block is primarily:",
                ["Preventive", "Detective signal of failed authentication",
                 "Corrective password reset", "Directive AUP"], 1,
                "Correct. 4625 records failure. Auto-block would be a separate preventive or "
                "corrective action. Remember: log of failure = detective."),
        ],
        goal=(
            "Learn what Security+ is, then classify a control by the job it does "
            "(preventive, detective, corrective, and related functions)."
        ),
        teach_back={
            "listener_prompt": (
                'Imagine a teammate says: "Every Security+ question mentions controls. '
                'What job did this control do?"'
            ),
            "explain_aloud": (
                "Security+ tests whether you can classify a control by its job, not by the tool brand. "
                "Preventive stops the bad thing before it succeeds, like a firewall DENY on remote desktop. "
                "Detective tells you something happened, like a SIEM alert on failed logons. "
                "Corrective limits damage after the fact, like isolating a laptop after malware ran. "
                "Directive tells people what to do, like a change ticket or acceptable use policy. "
                "Close with: preventive stops, detective watches, corrective cleans up, directive instructs."
            ),
            "define_first": [
                {
                    "term": "Control function",
                    "say": "Function means the job the control does: stop, watch, clean up, or instruct.",
                },
                {
                    "term": "Preventive control",
                    "say": "Preventive stops the event before it succeeds, like a block rule before a session starts.",
                },
                {
                    "term": "Detective control",
                    "say": "Detective notifies you that something happened; an alert alone does not block traffic.",
                },
            ],
            "desk_one_liner": (
                "On the desk: a SIEM burst alert is detective; isolating the host after execution is corrective; "
                "open remote desktop to a domain controller is a missing preventive control."
            ),
            "exam_trap": (
                "Calling a SIEM alert preventive because you wish it blocked the IP. "
                "Notify-only alerts are detective until a separate control blocks."
            ),
        },
    )

    add(
        "sp_d1_02_control_implementation", "d1_concepts", "1.1",
        "Technical, managerial, operational, physical", 17,
        ["Technical Control", "Managerial Control", "Operational Control", "Physical Control",
         "Compensating Control", "MFA"],
        [
            ("How is the control built?", """
                Last lesson: function = the job the control does (stop, watch, clean up).
                This lesson: implementation = how the control is built. The exam tests both
                ideas. Keep them separate.

                Where you see this at work: finance reports a fake vendor invoice. You revoke
                the CFO's sessions in Entra (software enforcement). The SOC shift lead follows
                the BEC playbook and calls finance back (people process). Leadership signs a
                written risk acceptance for legacy auth with an owner and end date (governance).
                The server cage badge reader still keeps strangers off the hardware.

                In Security+ terms, those builds are implementation types: technical,
                operational, managerial, and physical.

                Implementation types:
                  Technical: software or hardware enforcing a rule
                    Examples: firewall, EDR, MFA (multi-factor authentication), DLP
                    (data loss prevention), Conditional Access, BitLocker
                  Managerial: plans, policies, and ownership decisions
                    Examples: risk assessment, written policy, vendor security review,
                    documented exception with owner and review date
                  Operational: people doing security work on a schedule
                    Examples: SOC shift handoff, phishing awareness briefing, backup
                    restore test, weekly vuln-scan review
                  Physical: doors, cages, cameras protecting hardware and people
                    Examples: badge reader, server cage, CCTV, mantrap

                Technical specifics:
                  - MFA in Entra/Okta is technical even when the second factor is a phone.
                    Physical means facility controls, not "something you can touch."
                  - EDR isolate = technical corrective action. The IR playbook that tells
                    the analyst when to isolate = operational.
                  - Firewall DENY tcp/3389 = technical preventive. The standard that says
                    "no internet RDP" = managerial. The change ticket that pushed the rule
                    = directive (function) and usually managerial/operational process.
                  - Compensating control reminder: planned extra control when the preferred
                    one is missing, with owner and time limit. "Leave RDP open for the
                    vendor" with no documentation is unmanaged risk, not compensating.

                Worked example (BEC response stack):
                  1. Revoke sessions / disable legacy auth path → technical
                  2. Finance calls the vendor on a known-good number → operational
                  3. Written exception for a legacy mailbox app, owner + 30-day review →
                     managerial
                  4. Datacenter badge logs during the same window → physical / accounting aid

                The exam may ask only one axis. Answer the axis the question names.
                """),
            ("Keep the two axes apart on the exam", """
                When you read the question:
                  1. If it asks what job the control did, answer with function
                     (preventive / detective / corrective / ...).
                  2. If it asks how the control is built, answer with implementation
                     (technical / managerial / operational / physical).
                  3. You can combine them in speech ("detective technical SIEM rule")
                     but do not crush both ideas into one vague word on a multiple-choice.

                How to answer:
                  1. Circle the verb: blocked, alerted, cleaned up, documented, walked a beat.
                  2. Ask: is this about job or build?
                  3. Eliminate answers from the other axis.
                  4. For MFA/phone traps, remember: platform enforcement = technical.

                Common trap: calling MFA "physical" because a phone is involved.
                MFA is technical. Physical means doors and cages. Another near-miss:
                calling a SOC checklist "technical" because it mentions EDR. The checklist
                itself is operational.

                Remember: function = job. Implementation = build. Compensating is a planned
                extra control, not silent risk. The exam will ask which idea the question
                is testing.
                """),
        ],
        [
            _mc(
                "EDR isolating a host is which implementation type?",
                ["Managerial policy only", "Technical", "Physical badge", "AUP reprint"],
                1, "Software enforcing containment.",
                "Correct. EDR actions are technical. The IR playbook around them is "
                "operational. Remember: software enforcement = technical.",
            ),
            _mc(
                "A written risk acceptance for kill switch OFF with owner and review date is:",
                ["Technical firewall rule", "Managerial / governance artefact", "Physical CCTV", "Base64 encoding"],
                1, "Ownership and acceptance live in the program, not in a packet filter.",
                "Correct. Documented acceptance is managerial. Turning the kill switch ON "
                "would be technical mitigation. Remember: owner + date = managerial.",
            ),
            _mc(
                "Badge reader on the server cage is:",
                ["Technical SIEM", "Physical", "Detective only by definition", "Directive CHG ticket"],
                1, "Doors and cages.",
                "Correct. Physical protects the hardware plane your SIEM cannot see. "
                "Common trap: upgrading doors into 'technical' just because they have electronics. "
                "Remember: doors and cages = physical.",
            ),
            _mc(
                "Weekly SOC shift handoff checklist is primarily:",
                ["Physical", "Operational", "Encryption cipher", "Compensating RDP open"],
                1, "People process on a cadence.",
                "Correct. Operational = people doing security work on a schedule. "
                "Remember: checklists and briefings are operational.",
            ),
        ],
        [
            _qz("q_d1_02a", "MFA enforced in Entra is primarily:",
                ["Physical", "Technical", "Only managerial", "Deterrent poster"], 1,
                "Correct. Identity platform enforcement is technical. "
                "Common trap: phone in hand does not make MFA physical. "
                "Remember: platform enforcement = technical."),
            _qz("q_d1_02b", "SOC shift handoff checklist is:",
                ["Physical", "Operational", "Encryption", "Compensating RDP"], 1,
                "Correct. People process on a cadence = operational. "
                "Remember: checklists and briefings are operational."),
            _qz("q_d1_02c", "Vendor security questionnaire before buying a mail filter is:",
                ["Managerial / third-party review", "Physical", "Corrective isolate", "Hashing"], 0,
                "Correct. Due diligence before trust is managerial. "
                "Common trap: calling a questionnaire a packet filter. "
                "Remember: review before buy = managerial."),
            _qz("q_d1_02d", "Why separate function vs implementation in an interview?",
                ["To sound random", "So you can say 'detective technical' without mixing axes",
                 "Because CompTIA forbids both", "Only physical matters"], 1,
                "Correct. Clear axes show you can classify under pressure. "
                "Remember: that skill transfers straight to Security+ scenario questions."),
            _qz("q_d1_02e", "DLP rule blocking upload of payroll CSVs is primarily:",
                ["Physical cage", "Technical", "Only deterrent", "Directive AUP alone"], 1,
                "Correct. Software enforcing a data rule is technical. AUP may back it, "
                "but the block itself is technical. Remember: enforcement in software = technical."),
        ],
    )

    add(
        "sp_d1_03_cia_fundamentals", "d1_concepts", "1.2",
        "CIA triad in ticket language", 17,
        ["Confidentiality", "Integrity", "Availability", "Non-repudiation", "BEC"],
        [
            ("Which pillar did the question just break?", """
                The exam maps the scenario to a CIA pillar. CIA means Confidentiality,
                Integrity, and Availability. Memorizing the slogan is not enough. You have
                to name the impact in ticket language.

                Where you see this at work: a CFO mailbox rule forwards all finance mail to
                a personal Gmail. Secrets left the company. Separately, a new local admin
                account appears overnight with no ticket. Trust boundaries changed without
                authorization. Separately, a password spray locks out half of finance so
                nobody can reset a password to get work done.

                In Security+ terms, those impacts map to confidentiality, integrity, and
                availability.

                CIA in Boundry / SOC terms:
                  Confidentiality: unauthorized disclosure or collection
                    Clues: inbox forward-all, cleartext laptop theft, open file share with
                    SSNs, TLS missing on a login page
                  Integrity: unauthorized change to data, config, or trust
                    Clues: attacker-created local admin svc_backup2, altered firewall rule,
                    tampered invoice, unexpected Group Policy change
                  Availability: cannot use the system or data when needed
                    Clues: ransomware encrypting shares, account lockouts, DDoS, deleted
                    VM, VPN down with no failover

                Non-repudiation: you can prove who did an action. Signed mail, privileged
                account logging, ticket that names the analyst who isolated the host.
                Related idea: accountability. Not a fourth CIA letter, but the exam asks it
                next to CIA often.

                Technical specifics:
                  - BEC (business email compromise) forward rule → lead pillar is usually
                    confidentiality (mail contents leaving). Mail "still works," so
                    availability is the near-miss wrong answer.
                  - Ransomware on file shares → availability lead (files unusable), with
                    integrity of originals also damaged. Many questions accept availability
                    as the primary impact.
                  - Stolen CEO laptop, no BitLocker → confidentiality. Perfect SIEM does
                    not rescue a cleartext disk.
                  - Deception (honeypot / honeytoken): usually detective. High-confidence
                    alert, not your first SMB preventive control.

                Worked example: SigninLogs show legacy auth success for cfo@, then an inbox
                rule forwards *finance* to attacker@mail.tld. Users can still send mail.

                  Lead pillar: confidentiality (collection / disclosure)
                  Not availability: mail still flows
                  Integrity may enter later if the attacker alters payroll files
                  Non-repudiation aid: who disabled the rule, with ticket + logs
                """),
            ("Close the CIA trap questions", """
                How to answer:
                  1. What was lost, changed, or taken offline?
                  2. Pick the lead pillar the question is testing.
                  3. Do not force every outage into integrity.
                  4. If the question asks about proof of who acted, think non-repudiation.

                Common trap: calling external mail forward an availability issue because
                "email still works." Secrets leaving is confidentiality. Another near-miss:
                calling spray lockouts confidentiality because passwords were guessed.
                The user impact in that story is often availability of accounts.

                Remember: secrets leaving = confidentiality. Wrong or unauthorized change =
                integrity. Systems down or locked out = availability.
                """),
        ],
        [
            _mc(
                "CFO mailbox forward-all to personal Gmail primarily breaks:",
                ["Availability of the printer", "Confidentiality of mail contents",
                 "Integrity of the firewall rulebase only", "Physical cage locks"],
                1, "Secrets leaving to a personal inbox.",
                "Correct. External forward of finance mail is confidentiality (collection). "
                "Common trap: calling it availability because mail still 'works.' "
                "Remember: secrets leaving = confidentiality.",
            ),
            _mc(
                "New local admin svc_backup2 with no change ticket primarily threatens:",
                ["Integrity of privilege boundaries (and likely more)", "Only printer availability",
                 "Only CCTV", "Hashing algorithms"],
                0, "Unauthorized privileged account = trust boundary broken.",
                "Correct. Unexpected privilege breaks integrity of trust boundaries, and "
                "often confidentiality next. Remember: surprise admin = integrity hit.",
            ),
            _mc(
                "Spray lockouts blocking a legit password change hit which CIA pillar hardest for users?",
                ["Confidentiality of CCTV", "Availability of accounts", "Non-repudiation posters", "Physical only"],
                1, "Users cannot authenticate / work.",
                "Correct. Lockouts are availability impact even when the detective control "
                "was right to fire. Remember: detective can be correct and still create "
                "availability pressure.",
            ),
            _mc(
                "Ticket naming the analyst who isolated WS-HR-03 primarily supports:",
                ["Opening more RDP", "Non-repudiation / accountability",
                 "Deleting SigninLogs", "Legacy auth"],
                1, "Named actions create an audit trail.",
                "Correct. Non-repudiation is proving who did what. "
                "Remember: named actions = accountability trail.",
            ),
        ],
        [
            _qz("q_d1_03a", "Invoice.xlsm ransomware that encrypts shares primarily hits:",
                ["Availability (and integrity of data)", "Only physical doors", "Only AUP text", "Directive CHG"], 0,
                "Correct. Encrypted files are unavailable, and integrity of originals is "
                "gone. Remember: exam often accepts availability as the lead impact."),
            _qz("q_d1_03b", "Ticket naming who isolated the host supports:",
                ["Non-repudiation / accountability", "Opening more RDP", "Deleting logs", "Legacy auth"], 0,
                "Correct. Named actions create an audit trail. "
                "Remember: named actions = non-repudiation thinking."),
            _qz("q_d1_03c", "Honeytoken mailbox alert is best described as:",
                ["Preventive encryption", "Detective deception", "Physical badge", "RTO metric"], 1,
                "Correct. Deception triggers high-confidence detection. "
                "Common trap: treating it as your primary preventive for ransomware. "
                "Remember: honeytoken = detective."),
            _qz("q_d1_03d", "Unencrypted stolen CEO laptop is mainly:",
                ["Confidentiality failure", "Only availability of MFA", "Directive scan", "SOAR playbook"], 0,
                "Correct. Disk encryption is the confidentiality control for lost devices. "
                "Remember: SIEM health does not rescue cleartext disks."),
            _qz("q_d1_03e", "Attacker alters a firewall ALLOW for tcp/3389 with no ticket. Lead CIA hit?",
                ["Integrity of configuration / trust", "Only printer confidentiality",
                 "Non-repudiation poster", "Availability of coffee"], 0,
                "Correct. Unauthorized config change is an integrity failure, and it may "
                "enable later confidentiality loss. Remember: surprise rule change = integrity."),
        ],
    )

    add(
        "sp_d1_04_aaa_zero_trust", "d1_concepts", "1.2",
        "AAA, Zero Trust, gap analysis", 18,
        ["Authentication", "Authorization", "Accounting", "Zero Trust", "Gap Analysis",
         "Identification", "MFA", "Conditional Access"],
        [
            ("Who are you, what can you do, who logged it?", """
                Exam writers mix identification, authentication, authorization, and
                accounting on purpose. You separate them on purpose.

                Where you see this at work: ceo@boundry.example signs in from Frankfurt.
                The username identifies the account. Password + MFA proves it is that person
                (or someone with their factors). Conditional Access allows the Outlook session.
                SigninLogs and SIEM keep the row you paste into the ticket.

                In Security+ terms, that stack is identification, authentication (AuthN),
                authorization (AuthZ), and accounting. Together, AuthN + AuthZ + accounting
                are often called AAA.

                AAA beats:
                  Identification: username / UPN (user principal name, like name@domain)
                  Authentication: password, MFA, certificate, Windows Hello
                  Authorization: group, role, Conditional Access grant, NTFS ACL
                  Accounting: Windows 4624/4625, Entra SigninLogs, SIEM, ticket notes

                Technical specifics:
                  - MFA = multi-factor authentication = authentication, not identification.
                  - Conditional Access grant after MFA = authorization of the session/app.
                  - The SigninLogs row = accounting. Logs do not grant access.
                  - Legacy protocols (basic auth / older mail protocols) often skip modern
                    MFA prompts. That is an authentication control gap.
                  - Windows 4625 = failed logon (auth failed). 4624 = success (auth worked).
                    Neither row by itself is authorization to a specific file share.

                Worked example: CEO travel login.
                  AuthN: password + MFA passed
                  AuthZ: CA policy allowed Office apps because MFA + compliant device
                  Accounting: SigninLogs / SIEM row + HR travel confirmation in the ticket
                  Zero Trust angle: you trusted the session because factors and process
                  passed, not because "corporate VPN."
                """),
            ("Zero Trust and gap analysis on the exam", """
                Zero Trust: never trust network location alone. Authenticate and authorize
                every session. Assume breach. Prefer least privilege.

                Exposed RDP (TCP 3389) to a domain controller from the internet is the
                opposite of Zero Trust. "Inside the VPN = trusted" with no MFA is
                castle-and-moat thinking, not Zero Trust.

                Gap analysis: compare required control vs what you actually have.
                Example: NordVPN kill switch OFF is a confidentiality/availability risk if
                the tunnel drops. Name the gap, mitigate (turn it ON) or formally accept
                with owner and review date.

                How to answer:
                  1. Label each fact: identify / authenticate / authorize / account.
                  2. If the question says Zero Trust, reject "location alone = trusted."
                  3. If it says gap analysis, look for should-exist vs does-exist.
                  4. Do not call MFA identification.

                Common trap: calling MFA "identification." Username identifies. Factors
                authenticate. Another near-miss: calling the Conditional Access allow
                "accounting" just because it was logged. Allow = authorization. Log = accounting.

                Remember: logs = accounting. Location alone is not trust. Gap = should vs does.
                """),
        ],
        [
            _mc(
                "CEO sign-in from Frankfurt, MFA passed, HR confirms. The SIEM/SigninLogs row is:",
                ["Identification only", "Authorization that grants admin",
                 "Accounting / audit trail of the authenticated session", "A deterrent flight ban"],
                2, "Logs do not grant access; they record it.",
                "Correct. Accounting is the audit trail. MFA was authentication; CA/group "
                "was authorization. Remember: logs = accounting.",
            ),
            _mc(
                "Zero Trust ops definition that matches Boundry?",
                ["Trust anyone on VPN with no checks",
                 "Authenticate and authorize each session; location alone is not enough",
                 "Disable MFA for executives", "Open RDP to speed travel"],
                1, "Session policy, not 'VPN equals trusted'.",
                "Correct. ZT is continuous verification. Travel + MFA + process beats "
                "network faith. Common trap: 'inside = trusted.' Remember: verify each session.",
            ),
            _mc(
                "Kill switch OFF with no owner is a:",
                ["Closed gap", "Gap / untreated risk until mitigated or formally accepted",
                 "Proof of encryption", "Directive CHG for Nessus"],
                1, "Required control missing or weak.",
                "Correct. Gap analysis names the missing control. Mitigate (ON) or accept "
                "with owner and date. Remember: untreated with no owner stays a gap.",
            ),
            _mc(
                "Password + MFA together are best labeled as:",
                ["Identification only", "Authentication", "Physical only", "Directive AUP"],
                1, "Proving the claimed identity.",
                "Correct. Username identifies; factors authenticate. "
                "Remember: MFA is authentication.",
            ),
        ],
        [
            _qz("q_d1_04a", "Password + MFA together are:",
                ["Identification only", "Authentication", "Physical only", "Directive"], 1,
                "Correct. Proving who you are = authentication. "
                "Common trap: calling MFA identification. "
                "Remember: username identifies; factors authenticate."),
            _qz("q_d1_04b", "Conditional Access grant after MFA is:",
                ["Authorization", "Only accounting", "Hashing", "Deterrent"], 0,
                "Correct. Allowing the app/session is authorization. "
                "Common trap: calling the grant 'accounting' just because it was logged. "
                "Remember: allow = authorization."),
            _qz("q_d1_04c", "Trusting 'inside VPN' with no MFA is:",
                ["Strong Zero Trust", "Castle-and-moat thinking, not Zero Trust",
                 "Corrective IR", "Non-repudiation"], 1,
                "Correct. Network location is not a sufficient trust signal. "
                "Remember: that is the exam's favorite Zero Trust near-miss."),
            _qz("q_d1_04d", "Gap analysis compares:",
                ["Required control vs actual control state", "Only font colors on dashboards",
                 "RTO to RPO names only", "Base64 to AES always"], 0,
                "Correct. Find what should exist versus what does. Then mitigate or accept. "
                "Remember: should vs does = gap analysis."),
            _qz("q_d1_04e", "Windows 4624 success logon in SIEM is primarily which AAA piece?",
                ["Authorization to every file share", "Accounting of an authenticated session",
                 "Identification without authentication", "Physical mantrap"], 1,
                "Correct. 4624 records that authentication succeeded. Share access still "
                "needs authorization checks. Remember: success log = accounting of AuthN."),
        ],
    )

    add(
        "sp_d1_05_change_management", "d1_concepts", "1.3",
        "Change management that saves your shift", 17,
        ["Change Management", "Backout Plan", "Allow List", "Stakeholder Notification",
         "CAB", "False Positive"],
        [
            ("Authorized activity vs incident", """
                Change management exists so authorized activity is not treated as an
                incident, and unauthorized activity is. That is the exam point.

                Where you see this at work: SIEM lights up with sequential probes from
                JUMP-01. Before you page the on-call, you find ticket CHG-512: "quarterly
                vuln scan." Scanner identity matches. You document a false positive and
                move on. Later the same night, local admin svc_backup2 appears at 03:14
                with no ticket. That absence of change is the signal. You escalate.

                In Security+ terms, that process is change management: request, risk,
                approve, schedule, implement, verify, backout.

                Worked example / Boundry memory hooks:
                  JUMP-01 sequential probes + CHG-512 "quarterly vuln scan"
                    → false positive if scanner identity matches
                  New local admin svc_backup2 at 03:14, no change ticket
                    → escalate. Absence of change is the signal
                  VPN flap during documented ISP window CHG-441
                    → false positive unless kill switch failed or path looks hostile

                Process beats:
                  1. Request
                  2. Impact / risk assessment
                  3. Approval (right owner / CAB for high risk)
                  4. Schedule and stakeholder notification
                  5. Implement
                  6. Verify (did the change do what we wanted?)
                  7. Backout if verify fails

                Technical specifics:
                  - Allow-list / deny-list updates for scanner IPs belong in the same
                    ticket as the firewall or SIEM exception.
                  - Disabling legacy auth org-wide: verify in SigninLogs that legacy
                    success rows disappear; keep a backout path for a break-glass app.
                  - Internet RDP to a DC should rarely (preferably never) get approval.
                    Better architecture: VPN + PAM jump + MFA.
                  - Documentation is the next analyst's detection logic. Portfolio notes
                    (What / Why / Disposition / MITRE / Next) explain why a control exists
                    so nobody "cleans up" the DENY on 3389.
                """),
            ("Ownership is part of the control", """
                How to answer / how to work a change-shaped alert:
                  1. Check for a matching CHG and scanner/admin identity before escalate.
                  2. Stakeholder notification (finance before a mail-filter change).
                  3. Ask who can approve prod DC firewall changes. Not a random DM.
                  4. Demand backout + verify on any prod identity or network change.

                Common trap: escalating a scan-shaped alert without checking for a CHG,
                or closing privileged account creation as "admins do that" with no ticket.
                Another near-miss: treating the CHG number as if it were the firewall DENY
                itself. The ticket is directive/governance. The packet filter is technical.

                Remember: I check for a change ticket before I escalate a scan-shaped
                alert. The exam wants process, owner, backout, and verify.
                """),
        ],
        [
            _mc(
                "JUMP-01 scans with CHG-512 'quarterly vuln scan'. What is CHG-512 primarily?",
                ["A technical preventive that drops packets",
                 "A directive / change-management artefact explaining authorized activity",
                 "Proof of nation-state APT", "A cryptographic hash of Nessus"],
                1, "Change tickets explain authorized activity.",
                "Correct. Change records keep you from escalating authorized scanner traffic "
                "when identity matches. Common trap: treating CHG as the deny rule. "
                "Remember: CHG is directive/governance.",
            ),
            _mc(
                "svc_backup2 local admin at 03:14 with no ticket. Best first read?",
                ["Close as CHG noise", "Escalate: missing change is the signal",
                 "Only reboot the DC", "Disable SIEM"],
                1, "No change + privileged account = incident-shaped.",
                "Correct. Absence of change management is itself an indicator. "
                "Common trap: closing as noise because 'admins do that.' "
                "Remember: no ticket + privilege = escalate.",
            ),
            _mc(
                "Before disabling legacy auth org-wide you need:",
                ["No plan: just flip it", "Impact check, stakeholders, backout, verify in SigninLogs",
                 "Open more RDP", "Delete accounting logs"],
                1, "Change process prevents outages and blind spots.",
                "Correct. Verify step: legacy success disappears from SigninLogs after the "
                "change. Remember: exam loves backout + verify.",
            ),
            _mc(
                "Scanner IP allow-list update should live:",
                ["Only in a sticky note", "In the same change record as the firewall/SIEM update",
                 "Nowhere", "Only in an unofficial chat joke"],
                1, "One audit trail for detection and exceptions.",
                "Correct. Detection and allow-lists need the same ticket story. "
                "Remember: one ticket, one story.",
            ),
        ],
        [
            _qz("q_d1_05a", "Best habit before escalating scan-shaped alerts?",
                ["Ignore all scans", "Check for a matching change ticket / scanner identity",
                 "Open 3389", "Disable EDR"], 1,
                "Correct. Authorized vuln scans are common false positives when context matches. "
                "Remember: that habit is both ops gold and exam gold."),
            _qz("q_d1_05b", "Backout plan means:",
                ["Never change prod", "How you reverse the change if verify fails",
                 "Only a poster", "Deleting the CHG"], 1,
                "Correct. Backout is part of responsible change. "
                "Common trap: a plan with no reverse path. Remember: no backout = incomplete."),
            _qz("q_d1_05c", "Allow-list update for a scanner IP should live:",
                ["In a sticky note only", "In the same change record as the firewall/SIEM update",
                 "Nowhere", "Only in Slack jokes"], 1,
                "Correct. Detection and allow-lists need the same audit trail. "
                "Remember: one ticket, one story."),
            _qz("q_d1_05d", "Who should approve internet RDP to a DC?",
                ["Random intern DM", "Named owner / CAB with risk acceptance: preferably never approve it",
                 "The attacker", "No one ever documents it"], 1,
                "Correct. High-risk changes need real ownership, and better architecture "
                "usually means never approving internet RDP to a DC. "
                "Remember: owner or redesign, not hallway yes."),
            _qz("q_d1_05e", "Verify step after blocking legacy auth should check:",
                ["That SigninLogs no longer show legacy success for normal users",
                 "That all firewalls are powered off", "That MFA is removed", "That CHG is deleted"], 0,
                "Correct. Verify proves the change worked using the right telemetry. "
                "Remember: change without verify is incomplete."),
        ],
    )

    add(
        "sp_d1_06_crypto_soc", "d1_concepts", "1.4",
        "Cryptography the SOC actually touches", 18,
        ["Encryption", "Hashing", "Digital Signature", "PKI", "Obfuscation", "TLS", "BitLocker"],
        [
            ("Pick the property, not the cipher math", """
                On the Security+ exam you choose the right cryptographic property. You are
                not writing AES in Python. Cryptography here means using math and keys to
                protect confidentiality, integrity, or proof of origin.

                Where you see this at work: you hash Invoice.xlsm and paste the SHA-256 into
                a ticket so EDR and the mail gateway can hunt the same sample. You check that
                the Boundry dashboard uses HTTPS (TLS). The CEO laptop has BitLocker so a
                stolen disk is not open text. Someone runs powershell.exe -enc with Base64.
                That last one looks "crypto-ish" and is not encryption.

                In Security+ terms: encryption hides, hashing identifies/integrity-checks,
                signatures prove who sealed it, and obfuscation/encoding is not a
                confidentiality control.

                Property beats:
                  Encryption (confidentiality): BitLocker / FileVault; TLS on web apps;
                    encrypted backups; full-disk vs file-level
                  Hashing (integrity / stored secrets): file hash for IOC sharing;
                    password hashes in a directory; checksum after download
                  Digital signatures / certificates (PKI): code signing, HTTPS certs, S/MIME
                  Key stretching / salting: why unsalted password hashes fail under spray

                Technical specifics:
                  - TLS (Transport Layer Security): confidentiality and integrity in transit.
                    Handshake often uses public-key crypto, then a symmetric session key.
                  - BitLocker: confidentiality at rest for lost/stolen devices.
                  - Hash (SHA-256, etc.): one-way fingerprint. Does not hide contents.
                    Same file → same hash. Change one byte → different hash.
                  - Base64 / powershell -enc: encoding/obfuscation. Reversible without a
                    secret key. Tradecraft, not cryptography.
                  - Salt: random per-password value so identical passwords do not share
                    digests. Stretching (bcrypt/PBKDF2/Argon2) slows guessing.
                  - SOC failures the exam loves: expired cert, self-signed payment portal,
                    hard-coded API keys, NTLM fallback after Kerberos errors.

                Worked example: malware on HR PC.
                  1. Hash Invoice.xlsm → integrity/identification IOC (not encryption)
                  2. EDR shows powershell -enc → obfuscation, say that out loud
                  3. Confirm TLS on the phishing site clone vs real vendor (cert issues)
                  4. BitLocker status on CEO travel laptop is a separate confidentiality control
                """),
            ("Obfuscation is not encryption", """
                How to answer:
                  1. What property does the question need: hide, identify, or prove?
                  2. If there is no key and the blob is reversible, it is not encryption.
                  3. Match tool to property: BitLocker/TLS → confidentiality; hash →
                     integrity/ID; cert/signature → authenticity / non-repudiation aid.
                  4. "Appropriate" means right algorithm, right place, managed keys.

                Common trap: calling Base64 PowerShell (-enc) encryption. Another near-miss:
                treating a file hash as if it hid the malware. Hashes identify. They do not
                hide. Expired certs create availability friction and phishing lookalike trust
                issues when users click through warnings.

                Remember: hide = encrypt; identify = hash; prove = sign; Base64 ≠ encryption.
                """),
        ],
        [
            _mc(
                "Attacker used powershell.exe -enc <base64>. What is -enc here?",
                ["Encryption protecting confidentiality", "Obfuscation / encoding: not a confidentiality control",
                 "Vendor PKI signature", "bcrypt key stretching"],
                1, "Base64 is reversible without a key.",
                "Correct. Encoded command is tradecraft, not cryptography. "
                "Common trap: calling Base64 encryption. Remember: no key = not encryption.",
            ),
            _mc(
                "Hashing Invoice.xlsm for IOC sharing primarily supports:",
                ["Confidentiality of the file contents", "Integrity / identification of the sample",
                 "Opening RDP", "Directive AUP"],
                1, "Hashes identify content; they do not hide it.",
                "Correct. File hashes let EDR and mail gateway share an IOC without sending "
                "the malware. Common trap: treating a hash as encryption. "
                "Remember: hash identifies; it does not hide.",
            ),
            _mc(
                "BitLocker on the CEO laptop primarily protects:",
                ["Availability of SIEM", "Confidentiality if the device is stolen",
                 "Directive CHG text", "SOAR lockout"],
                1, "Lost device + encryption.",
                "Correct. Full-disk encryption is the classic confidentiality control for "
                "endpoints. Remember: stolen laptop → BitLocker → confidentiality.",
            ),
            _mc(
                "TLS on the Boundry analyst dashboard mainly provides:",
                ["Physical cage access", "Confidentiality (and integrity) in transit",
                 "CHG tickets", "Honeypots"],
                1, "HTTPS protects data in motion.",
                "Correct. TLS is encryption in transit. "
                "Remember: browser padlock story = TLS property, not hashing.",
            ),
        ],
        [
            _qz("q_d1_06a", "TLS on the Boundry dashboard mainly provides:",
                ["Physical access", "Confidentiality (and integrity) in transit", "CHG tickets", "Honeypots"], 1,
                "Correct. HTTPS protects data in motion. Remember: encryption in transit."),
            _qz("q_d1_06b", "Base64 PowerShell -enc is:",
                ["Strong encryption", "Obfuscation, not encryption", "A digital signature", "RPO"], 1,
                "Correct. Do not call encoding encryption on the exam or in interviews. "
                "Remember: Base64 ≠ encryption."),
            _qz("q_d1_06c", "Expired web cert risk includes:",
                ["Only prettier dashboards", "Availability friction + phishing lookalike trust issues",
                 "Faster spray", "Better RTO"], 1,
                "Correct. Users click through warnings; attackers abuse broken trust cues. "
                "Remember: broken trust cues help phishing."),
            _qz("q_d1_06d", "Password hashing without unique salts is weak because:",
                ["Hashes become wallpaper", "Identical passwords share digests; sprays/reuse hurt more",
                 "It opens 3389", "It disables MFA"], 1,
                "Correct. Salting and stretching are part of 'appropriate' stored-secret crypto. "
                "Remember: unique salt breaks shared digests."),
            _qz("q_d1_06e", "Code-signing certificate on a vendor updater primarily supports:",
                ["Availability of coffee", "Authenticity / integrity of the published binary",
                 "Opening SMB 445", "Directive AUP only"], 1,
                "Correct. Signatures help prove the publisher and that the file was not "
                "altered. Remember: sign = prove; encrypt = hide."),
        ],
    )
