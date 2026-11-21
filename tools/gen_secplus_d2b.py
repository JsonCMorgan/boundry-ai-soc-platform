"""D2 lesson specs for Phase 1 builder.

Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).
Depth: Option 1 ~15–20 min Show-me; work-facing picture + technical specifics.
SY0-801 new objectives (2.1 characteristics, 2.6 AI) live in gen_secplus_d2_801.py.
"""
from __future__ import annotations

from gen_secplus_d2_801 import (
    register_d2_801_ai,
    register_d2_801_characteristics,
    register_d2_801_quishing_deepfake,
)


def d2_specs(add, _mc, _qz):
    """Register Domain 2 micro-lessons (14 including SY0-801 deeper drills)."""

    # 801 objective 2.1 first in unlock order (characteristics before actors).
    register_d2_801_characteristics(add, _mc, _qz)

    add(
        "sp_d2_01_threat_actors", "d2_threats", "2.1",
        "Threat actors and motivations", 17,
        ["Threat Actor", "Insider Threat", "Ransomware", "Hacktivist"],
        [
            ("Motivation drives urgency", """
                Domain 2 asks you to compare threat actors and motivations. A threat actor is who (or what kind of group) is attacking. Motivation is why they bother. Motivation changes how fast you escalate.

                Where you see this at work: internet SMB probes on TCP 445 hit your firewall and are DROP. Later the same week you find ALLOW tcp/3389 from the internet to PROD-DC01. Same ports family, different urgency, because path and asset value differ.

                In Security+ terms, that is matching actor class and motivation to the evidence, then choosing urgency. You escalate open management paths to crown-jewel systems faster than failed commodity noise..

                Actor / motivation map (learn the classes):
                  1. Nation-state: persistence, stealth, long dwell, espionage or disruption
                  2. Organized crime / ransomware: money; spray → valid creds → encrypt
                  3. Hacktivist: disruption or public message
                  4. Insider (intentional): privilege abuse, staging data, no ticket admins
                  5. Insider (unintentional): CFO clicks Invoice.xlsm; missing travel note
                  6. Shadow IT / weak admin: exposed RDP 'just for the vendor'
                  7. Script kiddie / commodity: noisy scans that often never get through

                Technical specifics:
                - Commodity smell: many DROP rows on 445/3389, no internal follow-on
                  - Crime/ransomware smell: identity failures → success → remote access → encryption
                  - Insider smell: local admin created off-hours, no CHG, data staging shares
                  - You rarely 'prove nation-state' from one SIEM row. Pick the class the
                    evidence supports. Do not write an APT novel from a DROP burst.

                Worked example:
                Spray against 30 users, then encryption notes on a finance share.
                Best motivation class: organized crime / ransomware economics.
                Contrast: DROP-only 445 noise with no lateral movement stays commodity
                probe. Note the IOC. Do not page like domain compromise.

                How to answer on the exam:
                1. What path worked or is open?
                  2. What asset is at risk (DC, CFO mailbox, HR PC)?
                  3. Which motivation fits the evidence without drama?
                  4. Escalate to the urgency that path deserves.

                Common trap: treating every noisy scan as nation-state, or treating ALLOW 3389 to a DC like DROP noise. Path open to a crown jewel is not the same class as a failed probe.

                Remember: Motivation + path + asset value set urgency, not port noise alone.
                """),
            ("Talk-track that passes the exam and the interview", """
                Where you see this at work: your lead asks if this is APT. You say: evidence looks crime/commodity on identity and email paths. You are containing for ransomware stage-1, not writing a nation-state novel.

                In Security+ terms, that is evidence-first actor classification under time pressure..

                Hire talk-track beats:
                  1. Name the path (identity, email, remote access, supply chain).
                  2. Name the likely motivation class that fits.
                  3. Name the containment that interrupts money or privilege abuse.
                  4. Widen the hypothesis only when evidence disagrees.

                Technical specifics:
                - Unintentional insider still counts as human risk on the outline.
                  - Shadow IT exposing RDP is poorly skilled / unsanctioned admin risk,
                    not a compensating control.
                  - Hacktivist cues: defacement, loud disruption, public messaging.

                Worked example:
                New local admin at 03:14, no ticket. Keep insider or compromised admin identity on the table. Do not close as '445 noise' because privilege changed.

                How to answer on the exam:
                1. Reject movie plots without evidence.
                  2. Prefer the class that matches logs and business impact.
                  3. Say what you will contain next.

                Common trap: closing privileged change as script-kiddie noise because the perimeter is noisy.

                Remember: Pick the class the question actually shows. Contain the path.
                """),
        ],
        [
            _mc("Spray → valid creds → encrypt shares. Most likely actor motivation class?",
                ["Hacktivist protest only", "Organized crime / ransomware economics",
                 "Only physical thief", "Benign CHG-512"], 1,
                "Money path through identity.",
                "Correct. Crime crews monetize access. Treat spray as stage-0 of that path."
                "Common trap: follow the money motive when encryption of shares appears."),
            _mc("New local admin at 03:14, no ticket. Actor profile to keep on the table?",
                ["Only script kiddie 445 noise", "Insider or compromised admin identity",
                 "Only printer toner", "Authorized Nessus"], 1,
                "Privileged change without process.",
                "Correct. Intentional insider or stolen admin creds both fit until proven"
                "otherwise. Do not close as '445 noise' because privilege changed."),
            _mc("Internet SMB 445 DROP with no lateral movement. Best actor take?",
                ["Domain compromise tonight", "Commodity probe; perimeter held: note IOC",
                 "Identical to ALLOW 3389 on DC", "Proof of CFO BEC"], 1,
                "DROP ≠ breach.",
                "Correct. Failed inbound probe is not the same class as exposed RDP ALLOW."
                "Remember: DROP held ≠ ALLOW open."),
        ],
        [
            _qz("q_d2_01a", "Why escalate internet RDP to a DC faster than DROP 445 noise?",
                ["Fonts", "High-value path + likely crime/ransomware stage risk",
                 "445 is always worse", "RDP is always FP"], 1,
                "Correct. Asset tier + successful path matter. Exam cares about path and"
                "value, not just port noise."),
            _qz("q_d2_01b", "Unintentional insider example in Boundry stories:",
                ["Nation-state implant only", "CFO clicks Invoice.xlsm macro lure",
                 "Firewall DENY working", "Documented CHG scan"], 1,
                "Correct. Human vector, not malice. That still counts as insider risk. "),
            _qz("q_d2_01c", "Shadow IT exposing RDP is closest to:",
                ["Strong Zero Trust", "Poorly skilled / unsanctioned admin risk",
                 "Perfect compensating control", "Hashing"], 1,
                "Correct. Convenience without review. Compensating would be documented and owned. "),
            _qz("q_d2_01d", "Hacktivist motivation is usually:",
                ["Quiet long dwell only", "Disruption / message", "Backup restore tests", "RTO math"], 1,
                "Correct. Visibility and impact, not always stealthy theft. "),
        ],
    )

    add(
        "sp_d2_02_vectors_email_identity", "d2_threats", "2.2",
        "Vectors: email and identity", 17,
        ["Phishing", "BEC", "Password Spray", "Legacy Auth", "Attack Surface"],
        [
            ("Vector vs surface", """
                A vector is how they got in. An attack surface is what they could touch. Mixing those two words is a common miss on the exam.

                Where you see this at work: Invoice.xlsm lands in HR mail. Separately, one seasonal password is tried against thirty accounts from one IP. Separately, legacy mail auth creates an inbox rule without an MFA prompt.

                In Security+ terms, that is email and identity as primary vectors, with attack surface reduction as the fix that removes the path..

                Vector map:
                  1. Phishing / email: malicious docs, links, BEC vendor impersonation
                  2. Identity: password spray, brute force, credential stuffing, missing MFA
                  3. Legacy auth: older protocols that often skip modern MFA / CA prompts
                  4. Surface shrink: block internet macros, require MFA, disable legacy auth,
                     shrink local admin, block inbound management ports

                Technical specifics:
                - Spray: one password (or few), many users, often one src_ip, short window
                  - Brute: one user, many passwords / failures
                  - BEC collection: inbox rule, external forward, finance payment-change language
                  - Logs: 4625 bursts, Entra SigninLogs, mailbox audit for New-InboxRule
                  - Controls: ASR (Attack Surface Reduction) Office→script, mail gateway,
                    Conditional Access, disable basic/legacy auth

                Worked example:
                Password 'Summer2026!' against 30 accounts from one IP = spray, not pass-the-hash and not single-user brute. Primary vectors for CFO→Gmail via legacy auth = email/identity with weak auth protocol.

                How to answer on the exam:
                1. Name how entry happened (vector).
                  2. Name what was reachable (surface).
                  3. Pick the control that closes that path, not a random tool brand.

                Common trap: calling spray 'brute' or answering USB when the story is clearly mail and auth. Another near-miss: more dashboards while legacy auth stays on.

                Remember: Vector = how in. Surface = what they can touch. Close the path.
                """),
            ("Attack surface reduction that sticks", """
                Where you see this at work: you disable macros from the internet, turn off legacy auth, require MFA, and remove standing local admin from HR laptops after the third macro incident.

                In Security+ terms, that is attack surface reduction: remove paths attackers love..

                ASR checklist for Boundry-style stories:
                  1. Mail: block or sandbox risky attachments; train finance callbacks
                  2. Endpoint: stop Office from launching script hosts
                  3. Identity: MFA everywhere remote; disable legacy auth
                  4. Privilege: least local admin; PAM for admin tasks

                Technical specifics:
                - Legacy auth debt explains MFA-not-prompted inbox rules.
                  - Seasonal reused passwords make spray cheap.
                  - 'Be careful' alone is not surface reduction if excel→powershell still works.

                Worked example:
                Best surface shrink for Invoice.xlsm: block internet macros / ASR Office→script plus user training. Opening more SMTP relay is the opposite.

                How to answer on the exam:
                1. Find the open path in the question.
                  2. Prefer remove-path answers over detect-only answers when asked to mitigate.
                  3. Keep spray vs brute names separate.

                Common trap: treating awareness posters as enough while Office→PowerShell still runs.

                Remember: For Boundry-style incidents, start with identity plus email.
                """),
        ],
        [
            _mc("Password 'Summer2026!' against 30 accounts from one IP. Best name?",
                ["Password spray: one password, many users", "Pass-the-hash from a DC",
                 "Benign Defender scan", "Only brute against one UPN"], 0,
                "Breadth across accounts.",
                "Correct. Spray = many users / one password / usually one source. Brute"
                "is depth on one account. Keep those names separate for the exam."),
            _mc("Inbox rule CFO → Gmail via legacy auth. Primary vectors?",
                ["Only physical USB", "Email/identity path with weak auth protocol",
                 "Only VLAN mislabel", "Printer SNMP"], 1,
                "Mail + auth debt.",
                "Correct. BEC collection rides identity and mailbox features. USB is the"
                "distractor when the stem is clearly mail and auth."),
            _mc("Best surface shrink for Invoice.xlsm macros?",
                ["Open more SMTP relay", "Block internet macros / ASR Office→script + user training",
                 "Disable all logging", "Trust all attachments from finance"], 1,
                "Remove the execution path.",
                "Correct. Mail + endpoint controls beat 'be careful' alone. Exam wants"
                "surface reduction that removes the path."),
        ],
        [
            _qz("q_d2_02a", "Spray vs brute: spray is:",
                ["One user, many passwords", "One password (or few), many users",
                 "Only USB", "Only DNS"], 1,
                "Correct. Breadth vs depth. Spray = many users; brute = one user, many tries. "),
            _qz("q_d2_02b", "Legacy auth is dangerous because:",
                ["It always encrypts better", "It often bypasses modern MFA/CA prompts",
                 "It deletes SIEM", "It is a physical control"], 1,
                "Correct. Protocol debt skips controls. That is why exams hammer legacy auth. "),
            _qz("q_d2_02c", "BEC vendor-impersonation primarily uses which vector?",
                ["Email / social", "Only cage keys", "Only NIDS signatures", "RPO"], 0,
                "Correct. People + mail. Do not invent a network-IDS answer for a social vector. "),
            _qz("q_d2_02d", "Attack surface reduction example:",
                ["Expose more RDP", "Disable legacy auth and require MFA",
                 "Delete change tickets", "Turn off EDR"], 1,
                "Correct. Remove paths attackers love. More exposure is the opposite of ASR. "),
        ],
    )

    add(
        "sp_d2_03_vectors_remote_supply", "d2_threats", "2.2",
        "Vectors: remote access and supply chain", 16,
        ["RDP", "VPN", "Supply Chain", "Removable Media", "Default Credentials"],
        [
            ("Remote access paths", """
                Remote access is its own vector class: RDP, VPN, vendor jump hosts.

                Where you see this at work: firewall shows ALLOW tcp/3389 from 203.0.113.88 to PROD-DC01 with no VPN. A vendor jump box still has standing domain admin with no review date.

                In Security+ terms, that is remote access and supply-chain / third-party access vectors. Close them with path removal and lifecycle, not hope..

                Remote / supply map:
                  1. Exposed RDP/SSH management from the internet
                  2. VPN without MFA (encrypted tunnel, weak identity)
                  3. Vendor/MSP standing privilege
                  4. Default or seasonal passwords
                  5. Removable media and compromised updaters (less common on Boundry shifts,
                     still on the outline)

                Technical specifics:
                - RDP = TCP 3389. SSH = TCP 22. SMB = TCP 445.
                  - Fix for internet RDP to DC: remove exposure; VPN + MFA + PAM/jump.
                  - Default creds and Summer2026!-style reuse feed spray stories.
                  - Supply chain: trusted updater or MSP path abused with too much privilege.

                Worked example:
                ALLOW tcp/3389 from internet to PROD-DC01 = remote access / exposed management plane. Vendor jump with standing domain admin = supply-chain / third-party access risk, not Zero Trust success.

                How to answer on the exam:
                1. Name the remote path.
                  2. Ask if identity strength matches the path (MFA? PAM?).
                  3. Prefer remove-exposure answers over detect-only.

                Common trap: reframing a firewall ALLOW as 'only phishing,' or calling standing vendor admin a compensating control with no owner or expiry.

                Remember: Remote access and identity are default hypotheses. Widen when evidence disagrees.
                """),
            ("Supply chain and media", """
                Where you see this at work: an MSP account still has prod admin a year after the project ended, or HR finds a 'free USB giveaway' that auto-runs when plugged in.

                In Security+ terms, that is supply-chain and removable-media vectors sitting beside remote access on objective 2.2..

                When to widen beyond email/VPN:
                  1. Entry evidence does not fit mail or remote auth.
                  2. Binary came from a trusted updater channel that looks off.
                  3. First execution is from removable media.

                Technical specifics:
                - Removable media: USB/CD autorun or lure files from reception.
                  - Third-party: standing VPN/admin without review dates.
                  - Compensating would be documented, owned, time-boxed. Hallway yes is not.

                Worked example:
                Infected USB at reception = removable media vector. Still teachable even if rare on your shifts. Name the class.

                How to answer on the exam:
                1. Start with remote + identity hypotheses.
                  2. Widen when the entry evidence does not fit.
                  3. Pick the mitigation that closes that class.

                Common trap: never considering supply chain, or always blaming USB when logs show mail and legacy auth.

                Remember: Name the vector class, then pick the control that closes it.
                """),
            ("801 vectors: QR, messaging, IoT/OT, signals", """
                Where you see this at work: a parking-lot poster QR code opens a fake MFA
                page (quishing: phishing via QR). An RCS or SMS lure asks for a one-time
                code. A building controller on the OT (operational technology) VLAN talks
                plaintext to the internet. A rogue Bluetooth beacon near the lobby phones.

                In Security+ terms, that is expanded threat vectors and sources on SY0-801:
                image-based QR, richer messaging (SMS/RCS/IM), IoT/OT, and signal-based
                paths (NFC, RF, Bluetooth), not only email and RDP.

                Vector map add-ons:
                  1. QR / quishing: camera → malicious URL; often skips mail filters
                  2. SMS / RCS / IM / collab tools: OTP harvest, malicious links
                  3. CAPTCHA abuse: fake "prove you are human" pages that phish or install
                  4. IoT/OT: cameras, badge panels, PLCs with weak defaults and flat nets
                  5. Signal-based: NFC tap lures, RF spoofing, Bluetooth pairing abuse

                Technical specifics:
                  - Quishing smell: sudden QR on invoice printouts, parking signs, badge
                    stickers. User phone hits unknown domain; Entra shows MFA fatigue or
                    new device.
                  - OT vs IT: do not treat a plant controller like a laptop. Segment OT;
                    never flat-route OT to the internet for "convenience."
                  - IoT: default creds, UPnP, cloud callbacks. Inventory and VLAN isolate.
                  - Signal path: evil twin Wi-Fi and Bluetooth impersonation still need
                    identity proof (callback, known SSID policy), not hope.

                Worked example:
                Invoice PDF is clean, but the printed remittance QR goes to pay-evil.example.
                Vector class is image-based / QR (quishing), not "only attachment macros."
                Contain with user report, URL block, and finance callback on payment changes.

                How to answer on the exam:
                  1. Name the delivery channel the question shows (QR, RCS, IoT, RF).
                  2. Do not force-fit email if the phone camera or radio path is the entry.
                  3. Prefer segmentation + identity proof for OT/IoT answers.

                Common trap: calling every lure "email phishing" when the story is a QR
                sticker or an OT flat network. Near-miss: opening OT to the internet "for
                the vendor" without a brokered jump path.

                Remember: Channel matters. QR, chat, IoT/OT, and radio are first-class vectors.
                """),
        ],
        [
            _mc("ALLOW tcp/3389 from internet to PROD-DC01. Vector class?",
                ["Removable media only", "Remote access / exposed management plane",
                 "Only phishing PDF", "Directive AUP"], 1,
                "Internet RDP is a remote vector.",
                "Correct. Management protocols on the open internet are high-value vectors."
                "Do not reframe a firewall ALLOW as 'only phishing.'"),
            _mc("Vendor jump with standing domain admin and no review is:",
                ["Great Zero Trust", "Supply-chain / third-party access risk",
                 "Only a physical issue", "Proof of hashing"], 1,
                "Trusted path abuse.",
                "Correct. MSP privilege is a supply-chain style surface. Standing admin"
                "without review is the exam's favorite third-party miss."),
            _mc("Infected USB dropped at reception is:",
                ["Impossible on the outline", "Removable media vector",
                 "Only SIEM misconfig", "RTO"], 1,
                "Classic physical→endpoint path.",
                "Correct. Still teachable even if rare on your shifts. Name the vector class. "),
            _mc("Parking-lot poster QR opens a fake MFA page. Best vector label?",
                ["Only CVE misconfiguration", "Image-based / QR quishing path",
                 "Only OT PLC firmware", "Directive change ticket"], 1,
                "QR delivers the lure outside mail filters.",
                "Correct. Quishing is phishing via QR. "
                "Common trap: forcing an email-attachment answer. "
                "Remember: camera path still counts as a vector."),
        ],
        [
            _qz("q_d2_03a", "Best first fix for internet RDP to a DC?",
                ["More dashboards only", "Remove exposure; VPN/PAM/MFA jump",
                 "Disable logging", "Longer passwords on the attacker"], 1,
                "Correct. Close the path. Dashboards without path removal fail Domain 2 and 3. "),
            _qz("q_d2_03b", "VPN without MFA is:",
                ["Perfect ZT", "Weaker remote vector control", "Physical only", "PBQ"], 1,
                "Correct. Remote access needs strong authn. Encrypting the tunnel is not enough. "),
            _qz("q_d2_03c", "Default credentials matter because:",
                ["They decorate SIEM", "Attackers spray known defaults and seasonal passwords",
                 "They improve RPO", "They replace backups"], 1,
                "Correct. Predictable secrets. That is why password hygiene sits with vectors. "),
            _qz("q_d2_03d", "When do you widen beyond email/VPN hypotheses?",
                ["Never", "When entry evidence does not fit those paths",
                 "Only on Saturdays", "Only if RTO is zero"], 1,
                "Correct. Hypothesis-driven triage. Stay flexible when evidence disagrees. "),
            _qz("q_d2_03e", "Flat OT VLAN with internet-facing controllers is mainly:",
                ["A strong Zero Trust win", "IoT/OT vector and segmentation failure",
                 "Only a managerial poster issue", "Proof hashing is complete"], 1,
                "Correct. OT/IoT paths need segmentation and brokered access. "
                "Common trap: treating plant gear like a hardened laptop. "
                "Remember: OT flat-to-internet is a vector."),
        ],
    )

    add(
        "sp_d2_04_vulns_misconfig", "d2_threats", "2.3",
        "Vulnerabilities: software and misconfiguration", 17,
        ["Vulnerability", "Misconfiguration", "CVE", "Unpatched", "Insecure Design"],
        [
            ("Types that match tickets", """
                A vulnerability is a weakness that can be exploited. It is not only a CVE number. Misconfiguration and insecure design count.

                Where you see this at work: Nessus ticket SEC-220 lists a CVE on the VPN client. Separately, the firewall ALLOW for 3389 to the DC has no CVE at all and is still critical.

                In Security+ terms, that is software vulnerabilities, misconfigurations, weak configuration, and insecure design as first-class vulnerability types..

                Vulnerability types:
                  1. Unpatched software / known CVE
                  2. Misconfiguration (ALLOW 3389 to DC; kill switch OFF)
                  3. Weak configuration (legacy auth on; NTLM fallback)
                  4. Default / abandoned privileged accounts
                  5. Insecure design (silent external mail forward with no guardrail)
                  6. Zero-day: unknown to vendor; you detect behavior and contain

                Technical specifics:
                - CVE = Common Vulnerabilities and Exposures ID. Useful, not required
                    for something to be a vuln.
                  - Scanner input feeds vuln management. Exposure without CVE still pages.
                  - Zero-day response starts with EDR parent/child and containment, not
                    guessing a CVE name.

                Worked example:
                ALLOW 3389 to DC with no CVE = still a vulnerability (misconfiguration / exposure). Legacy auth enabled = weak / insecure configuration. Mailbox auto-forward to Gmail with no control = insecure design / missing data control.

                How to answer on the exam:
                1. Ask: weakness that enables abuse?
                  2. Do not require a CVE string.
                  3. Prioritize by exploitability and asset value.

                Common trap: 'no CVE means safe.' Open management ports and protocol debt disagree.

                Remember: No CVE ID does not mean safe. Misconfig can outrank a medium CVE.
                """),
            ("Zero-day realism and human factors", """
                Where you see this at work: EDR shows a new parent/child chain you have never seen. There is no CVE in the ticket yet. You isolate and hunt behavior anyway.

                In Security+ terms, that is behavior-first response when the vulnerability name is unknown, plus human-factor weaknesses..

                Also vulnerabilities:
                  - Reused seasonal passwords
                  - No travel notice process
                  - Standing service accounts with admin

                Technical specifics:
                - Detect: EDR telemetry, unusual script hosts, odd egress.
                  - Contain: isolate host, revoke sessions, block hash/URL.
                  - Patch when a fix exists; compensate when it does not.

                Worked example:
                Zero-day response starts with behavioural detection and containment. Guessing the CVE name is optional. Containing is not.

                How to answer on the exam:
                1. Name the weakness class.
                  2. If unknown vuln, still contain on behavior.
                  3. Pair human factors with technical guardrails.

                Common trap: waiting for a CVE article before isolating a clearly malicious execution chain.

                Remember: Vulnerability = exploitable weakness. Contain what it does.
                """),
            ("801 surfaces: LLMs, repos, shadow IT, stale creds", """
                Where you see this at work: a public GitHub repo has a cloud access key in
                an old commit. An S3-style bucket is world-readable. A team spins a shadow
                IT SaaS with company mail and no SSO. A service account password has not
                rotated in four years. Staff paste proprietary code into a public LLM.

                In Security+ terms, that is expanded attack surfaces and vulnerability
                types on SY0-801: LLMs, public repositories, public object storage, shadow
                IT, and unmanaged or stale credentials.

                Surface map:
                  1. Public repos / object storage: secrets and data exposure without a CVE
                  2. Shadow IT: unsanctioned apps widen identity and data paths
                  3. Stale credentials: forgotten keys and service accounts still work
                  4. LLM paste / agent misuse: confidentiality loss and prompt abuse
                     (pair with objective 2.6 for AI-specific names)

                Technical specifics:
                  - Secret scanning in CI and cloud posture tools catch keys in repos/buckets.
                  - Inventory SaaS with SSO/CASB-style visibility; unsanctioned OAuth grants
                    are an identity surface.
                  - Stale creds: disable, rotate, prefer workload identities over long-lived
                    keys. Monitor unused privileged accounts.
                  - Public object storage: check ACLs and public-access blocks, not only CVEs.

                Worked example:
                "No CVE on the bucket" does not mean safe if the ACL is public-read on
                customer exports. Class: public object storage misconfiguration / exposure.

                How to answer on the exam:
                  1. Look for exposure words (public, world-readable, unsanctioned).
                  2. Prefer inventory + remove/rotate answers over "wait for a CVE."
                  3. Keep LLM paste under data-loss / surface, not "only phishing."

                Common trap: ignoring shadow IT because it is "not on the asset list."
                Near-miss: treating a leaked API key as "just a documentation issue."

                Remember: Surfaces include SaaS, storage, repos, and AI paste, not only CVEs.
                """),
        ],
        [
            _mc("ALLOW 3389 to DC with no CVE ID. Still a vulnerability?",
                ["No: no CVE means safe", "Yes: misconfiguration / exposure is a vuln class",
                 "Only if printer is down", "Only physical"], 1,
                "Not all vulns are CVEs.",
                "Correct. Exposure and misconfig are first-class vulnerability types."
                "Common trap: 'no CVE, so ignore.'"),
            _mc("Legacy auth enabled is best typed as:",
                ["Strong design", "Weak / insecure configuration", "Physical control", "RTO"], 1,
                "Protocol setting debt.",
                "Correct. Weak configuration enables BEC-style paths. Call it configuration debt. "),
            _mc("Mailbox auto-forward to Gmail with no control is:",
                ["Insecure design / missing data control", "Perfect DLP",
                 "Only a CHG success", "Hashing"], 0,
                "Feature without guardrails.",
                "Correct. Design that permits silent exfil is a vuln even before malware. "),
            _mc("World-readable cloud bucket of customer exports with no CVE is:",
                ["Safe because scanners found no CVE", "Public object storage exposure / misconfig",
                 "Only a physical cage failure", "Proof of perfect DLP"], 1,
                "ACL exposure is a vulnerability class.",
                "Correct. Public storage is an attack surface. "
                "Common trap: requiring a CVE before caring. "
                "Remember: public ACL can outrank a medium CVE."),
        ],
        [
            _qz("q_d2_04a", "Nessus finding vs open RDP misconfig:",
                ["Only CVE counts", "Both are vulnerability inputs; misconfig can be worse",
                 "Misconfig is never a vuln", "Ignore both"], 1,
                "Correct. Prioritize by exploitability and asset, not by presence of a CVE string. "),
            _qz("q_d2_04b", "Kill switch OFF is:",
                ["Misconfiguration / control gap", "Encryption", "Directive only", "Honeypot"], 0,
                "Correct. Expected control not enabled. That is a gap. "),
            _qz("q_d2_04c", "Zero-day response starts with:",
                ["Guessing the CVE name", "Behavioural detection and containment",
                 "Opening RDP", "Deleting EDR"], 1,
                "Correct. You hunt what it does. Naming the CVE is optional; containing is not. "),
            _qz("q_d2_04d", "Default service account with admin is:",
                ["Hardening success", "Credential / account hygiene vulnerability",
                 "Only availability", "PBQ font"], 1,
                "Correct. Standing privilege + predictable identity = hygiene failure. "),
            _qz("q_d2_04e", "API key committed to a public repo is mainly:",
                ["Proof the firewall is fine", "Public repository / secret exposure surface",
                 "Only a managerial poster gap", "A successful honeypot"], 1,
                "Correct. Public repos are an 801 attack-surface class. "
                "Common trap: waiting for a CVE on the key string. "
                "Remember: rotate, revoke, and scan commits."),
        ],
    )

    add(
        "sp_d2_05_vulns_human", "d2_threats", "2.3",
        "Vulnerabilities: human and process gaps", 17,
        ["Social Engineering", "Shadow IT", "Process Gap", "Awareness"],
        [
            ("Humans are in the outline for a reason", """
                Human and process gaps are real vulnerability classes on Security+. A vulnerability is a weakness an attacker can use. Here the weakness is people, process, or missing ownership, not only a CVE string.

                Where you see this at work: finance pays from a single email without a callback. HR keeps clicking macro invoices. A vendor VPN account has no review date. Awareness was last updated fourteen months ago.

                In Security+ terms, that is social engineering exposure, shadow IT, and process gaps as vulnerabilities.

                Human / process map:
                  1. Social engineering success paths (phishing, BEC pressure)
                  2. Password hygiene failures (reused Summer2026!)
                  3. Missing travel / verification process
                  4. Shadow IT and unsanctioned remote access
                  5. No owner / no review date on exceptions

                Technical specifics:
                - Process gap creates alert debt (travel login without HR note).
                  - Callback on payment-change emails reduces BEC payoff.
                  - Tech still required: ASR, MFA, disable legacy auth, DLP forwards.
                  - Shadow IT smell: personal Gmail forward, rogue VPN, unsanctioned SaaS with company data and no owner.
                  - Exception without expiry is a standing vulnerability, same class as an open management port with no ticket.
                  - Reused seasonal passwords across many users turn spray into a predictable hit rate.

                Worked example:
                CEO travel login without HR note = process gap that forces extra validation, not automatic ransomware.
                Repeat Invoice.xlsm clicks = human vulnerability plus missing technical macro controls (ASR / mail gateway).
                Vendor VPN with no review date = process / governance gap. Prefer: owner + expiry + access review. Near-miss: ignore because 'the firewall exists.'

                                More desk clues:
                  - Shadow IT smell: personal forward, rogue VPN, unsanctioned SaaS with company data.
                  - Exception without expiry is a standing vulnerability. Demand owner + review date.
                  - Reused seasonal passwords raise spray hit rate across many users.
                  - Pair every awareness theme with a technical guardrail (ASR, MFA, DLP, callback).

                How to answer on the exam:
                1. Name the human or process weakness.
                  2. Pair coaching with a technical guardrail.
                  3. Reject shame-only answers.
                  4. Ask who owns the exception and when it expires.

                Common trap: public shaming as the 'control,' or ignoring process gaps because a firewall exists. Another near-miss: treating missing travel notes as automatic ransomware true-positives with no other evidence.

                Remember: Do not shame. Contain, coach, and redesign the path.
                """),
            ("Contain and redesign", """
                Where you see this at work: after an unintentional click you isolate the host, reset the user, add ASR, and schedule role-based awareness for finance. You do not dunk on them in all-hands.

                In Security+ terms, that is treating unintentional insider risk as a control failure, not a character failure.

                Good response framing:
                  1. Contain impact
                  2. Coach the person
                  3. Add technical guardrails
                  4. Fix ownership on the exception that allowed the path

                Technical specifics:
                - Near-miss answer on the exam: only mock the clicker.
                  - Strong answers: ASR + role training + MFA/legacy fixes.
                  - Role-based awareness for finance beats org-wide poster-only.
                  - After contain: open a ticket that names the process owner and the technical control that should have blocked the path.

                Worked example:
                Best response for unintentional insider: contain impact, coach, add technical guardrails. Disable-all-accounts-forever is overkill theater. Poster-only while Office can still launch powershell.exe is incomplete.

                How to answer on the exam:
                1. Remove shame-only choices.
                  2. Prefer dual-layer fixes (people + tech).
                  3. Tie process gaps to owners and review dates.

                Common trap: 'only fire the analyst' or 'only mock the clicker' when the path is still open.

                Remember: The control failed, including the people process. Fix both layers.
                """),
        ],
        [
            _mc("CEO travel login without HR note looks like:",
                ["Automatic TP ransomware", "Process gap that forces extra validation",
                 "Proof to open 3389", "Directive CHG for Nessus"], 1,
                "Missing process creates alert debt.",
                "Correct. Travel process reduces FP pain and speeds true BEC detection."
                "Do not auto-declare ransomware from a missing note alone."),
            _mc("Repeat Invoice.xlsm clicks in HR. Vulnerability view?",
                ["Only fire the analyst", "Human + missing technical macro controls",
                 "Only physical doors", "Ignore"], 1,
                "Pair people and tech.",
                "Correct. Awareness alone is incomplete if Office→PS still works. Exam"
                "wants both layers."),
            _mc("Best response framing for unintentional insider?",
                ["Public shaming", "Contain impact, coach, add technical guardrails",
                 "Disable all accounts forever", "Delete logs"], 1,
                "Ops professionalism.",
                "Correct. Treat the risk, not the person's dignity. Shame answers are near-misses. "),
        ],
        [
            _qz("q_d2_05a", "Reused 'Summer2026!' across 30 users is:",
                ["Strong crypto", "Human / password hygiene vulnerability",
                 "Physical only", "RPO"], 1,
                "Correct. Predictable human secrets. That is a human vulnerability class. "),
            _qz("q_d2_05b", "No review date on vendor VPN is:",
                ["Process / governance gap", "Perfect ZT", "Hashing", "NIDS"], 0,
                "Correct. Standing access without lifecycle is a process gap. "),
            _qz("q_d2_05c", "Callback for payment-change emails reduces:",
                ["Disk encryption need to zero", "BEC / social engineering success",
                 "Need for SIEM", "RTO to zero automatically"], 1,
                "Correct. Process control on finance. It does not replace SIEM or encryption. "),
            _qz("q_d2_05d", "Near-miss answer on human vulns:",
                ["Add ASR + role training", "Only mock the clicker in all-hands",
                 "Disable legacy auth", "MFA everywhere"], 1,
                "Correct. Shame is not a control strategy. Pick the distractor that only mocks. "),
        ],
    )

    pbq_spray = {
        "id": "pbq_d2_spray",
        "kind": "pick",
        "title": "Name the identity pattern",
        "prompt": (
            "SIEM: 30 distinct users, same password failure cluster, one src_ip, 8 minutes. "
            "No 4624 success yet. What is it, and what do you do first?"
        ),
        "choices": [
            {"id": "spray", "text": "Password spray: block/rate-limit source, watch for success, reset hot accounts, escalate"},
            {"id": "brute", "text": "Brute force on one user only: ignore other UPNs"},
            {"id": "fp", "text": "Close FP: many failures always mean CHG scanner"},
            {"id": "rdp", "text": "Open inbound 3389 to investigate live"},
        ],
        "answer": "spray",
        "explain": (
            "Correct. Many users / one source / short window = spray. Contain the source and hunt"
            "successes. Common trap: ignoring other UPNs is the brute distractor. "
        ),
    }

    add(
        "sp_d2_06_ioc_identity", "d2_threats", "2.4",
        "Indicators: spray vs brute", 18,
        ["Password Spray", "Brute Force", "Indicator of Compromise", "SigninLogs"],
        [
            ("Smell the pattern: spray vs brute", """
                An indicator of compromise (IOC) is evidence that abuse may be happening or already happened. For identity, read the pattern before you pick a name.

                Where you see this at work: SIEM shows thirty distinct users failing from one IP in eight minutes with the same seasonal password. Separately, jsmith has 47 failures then a 4624 success.

                In Security+ terms, that is password spray versus brute force, plus travel-login validation..

                Pattern map:
                  1. Spray: one src_ip, many users, same/few passwords, short window
                  2. Brute: one user, many failures, watch for success
                  3. After either: hunt successful logons from the attacking IP
                  4. Travel: new country + MFA pass is not automatic true-positive

                Technical specifics:
                - Windows 4625 = failed logon. 4624 = success.
                  - SPL habit: event_type=logon_failed | stats count by src_ip
                  - KQL habit: dcount(UserPrincipalName) by IPAddress on SigninLogs
                  - Success after failures is the pivot. Failures are smoke; success is fire.

                Worked example:
                30 accounts, one IP, one seasonal password, 10 minutes = password spray. 47 failures on jsmith then 4624 = hunt the success session hard. ceo@ Frankfurt, MFA pass, HR confirms conference = likely FP with documented travel validation.

                How to answer on the exam:
                1. Count users vs failures-per-user.
                  2. Name spray or brute.
                  3. Hunt success sessions next.
                  4. For travel, validate process before FP stamp.

                Common trap: closing spray as scanner noise, or calling travel+MFA benign forever with no HR/process check when other BEC clues exist.

                Remember: Spray = breadth. Brute = depth. Always hunt the success.
                """),
            ("Travel vs spray", """
                Where you see this at work: Frankfurt sign-in with MFA and a conference on the calendar versus Frankfurt with no travel note, legacy auth, and a new inbox rule.

                In Security+ terms, that is using process context to separate travel false positives from BEC-shaped identity abuse..

                Validation beats:
                  1. MFA pass ≠ automatically benign
                  2. HR / calendar confirmation supports FP with a note
                  3. Legacy auth + mailbox rule + money language = contain

                Technical specifics:
                - SigninLogs fields: location, app, client app, legacy vs modern, MFA detail
                  - Pair identity IOC with mailbox audit when finance is involved

                Worked example:
                Travel + MFA + HR = FP with a note, not blind trust forever. Travel login with MFA but no HR note: validate before FP.

                How to answer on the exam:
                1. List identity IOCs.
                  2. Add process context.
                  3. Choose contain vs documented FP.

                Common trap: automatic ransomware true-positive from a missing travel note alone.

                Remember: MFA pass does not auto-mean benign if process context is missing.
                """),
        ],
        [
            _mc("30 accounts, one IP, one seasonal password, 10 minutes. Pattern?",
                ["Password spray", "Credential stuffing against a single UPN only",
                 "Pass-the-hash", "Benign Defender"], 0,
                "Breadth.", "Correct. Spray = many users / one password / usually one source."
                "Single-UPN answers are the brute/stuffing distractors."),
            _mc("47 failures on jsmith, then 4624 success. Priority?",
                ["Ignore success", "Hunt the success session hard: brute may have worked",
                 "Only close as FP", "Open RDP"], 1,
                "Success after failures is the pivot.",
                "Correct. Contain and investigate the authenticated session. Failures are"
                "smoke; success is fire."),
            _mc("ceo@ Frankfurt, MFA pass, HR confirms conference. Best disposition?",
                ["Automatic ransomware TP", "Likely FP with documented travel validation",
                 "Open 3389", "Disable SIEM"], 1,
                "Context.", "Correct. Travel + MFA + HR = FP with a note, not blind trust forever. "),
        ],
        [
            _qz("q_d2_06a", "Best spray hunt aggregation?",
                ["count by src_ip / dcount users", "Only printer toner", "Delete 4625", "Ignore IPs"], 0,
                "Correct. Source breadth. Aggregate by IP and distinct users. "),
            _qz("q_d2_06b", "Brute force signature:",
                ["Many users, one password", "One user, many failures",
                 "Only USB", "Only DNS tunnel"], 1,
                "Correct. Depth on one account. Flip of spray. "),
            _qz("q_d2_06c", "After spray, you must also:",
                ["Never look for 4624/success", "Hunt successful logons from the attacking IP",
                 "Disable accounting", "Trust VPN blindly"], 1,
                "Correct. Failures are the smoke; success is the fire. "),
            _qz("q_d2_06d", "Travel login with MFA but no HR note:",
                ["Always close FP", "Validate before FP: missing process raises BEC risk",
                 "Open RDP", "Delete SigninLogs"], 1,
                "Correct. Process gap. Validate before you stamp FP. "),
            _qz("q_d2_06e", "Best spray hunt aggregation in SIEM/KQL terms?",
                ["dcount of users (or count by src_ip) in a short window",
                 "Only printer toner counts", "Delete all 4625 rows first",
                 "Ignore source IP forever"], 0,
                "Correct. Spray smell is breadth across users from one source. "
                "Common trap: treating it like single-user brute. "
                "Remember: aggregate users by source IP."),
        ],
        pbq_spray,
    )

    pbq_bec = {
        "id": "pbq_d2_bec",
        "kind": "pick",
        "title": "BEC first move",
        "prompt": (
            "New inbox rule on cfo@ forwards all mail to personal Gmail. East EU IP, "
            "legacy auth, MFA not prompted. Finance has a vendor-payment change in draft. "
            "First mitigation that fits?"
        ),
        "choices": [
            {"id": "contain", "text": "Revoke sessions, remove the rule, reset credentials, escalate as BEC / collection"},
            {"id": "travel", "text": "Close as travel FP and add Frankfurt as trusted forever"},
            {"id": "poster", "text": "Only send a company-wide poster and stop"},
            {"id": "rdp", "text": "Open inbound 3389 so finance can check the server"},
        ],
        "answer": "contain",
        "explain": (
            "Correct. BEC / mailbox persistence. Contain identity and the rule first. Awareness comes"
            "after, not instead. Common trap: poster-only responses. "
        ),
    }

    add(
        "sp_d2_07_ioc_bec", "d2_threats", "2.4",
        "Indicators: BEC and mailbox collection", 18,
        ["BEC", "Inbox Rule", "Mailbox Forwarding", "Legacy Auth"],
        [
            ("BEC indicator pack", """
                BEC means business email compromise: abusing mail and identity to collect information or redirect money. An indicator of compromise (IOC) is evidence that abuse may be happening or already happened.

                Where you see this at work: cfo@ gets a new inbox rule forwarding everything to personal Gmail. Client used legacy auth. MFA was not prompted. Finance has a vendor payment-change draft waiting.

                In Security+ terms, that is mailbox collection / BEC indicators and identity-first containment.

                BEC IOC pack:
                  1. New inbox rule or external forward-all
                  2. Strange mail client / legacy auth / MFA skipped
                  3. Finance-themed lure or payment-change language
                  4. Unusual sign-in location or impossible travel without process

                Technical specifics:
                - Contain: revoke sessions, remove rule, reset credentials, escalate
                  - Eradicate contributors: disable legacy auth, alert/block external forwards
                  - CIA lead impact: confidentiality / collection (mail still 'works')
                  - MITRE-ish family: email/mailbox collection
                  - Mailbox audit / unified audit: New-InboxRule, Set-Mailbox forwarding, odd client apps
                  - SigninLogs: legacy vs modern, MFA detail, location, impossible travel context
                  - Payment-change draft after rule creation = fraud staging, not 'busy CFO'

                Worked example:
                First fit mitigation: revoke sessions, remove rule, reset, escalate BEC.
                Poster-only is incomplete. Closing as travel FP is how wire fraud happens.
                Contrast: travel login + MFA + HR conference note with no rule and no payment language = validate and document FP, not blind trust forever.

                                More desk clues:
                  - Mailbox audit / UAL: look for New-InboxRule, Set-Mailbox forwarding, unusual client apps.
                  - SigninLogs: legacy vs modern, MFA detail, location, impossible travel context.
                  - Finance path: payment-change language in drafts/sent items after rule creation.
                  - Eradication backlog after contain: disable legacy auth, forward controls, CA hardening.

                How to answer on the exam:
                1. Recognize the pack.
                  2. Contain identity and mailbox persistence first.
                  3. Warn finance / use callback process.
                  4. Fix protocol debt after the firefight.

                Common trap: 'email is normal business, close FP' while an external forward-all rule is live. Near-miss: awareness poster as the primary response while the rule still forwards.

                Remember: Rule + legacy auth + money language = contain now.
                """),
            ("Near-miss responses", """
                Where you see this at work: leadership wants only a company-wide poster after confirmed BEC.

                In Security+ terms, that is why awareness alone is incomplete after mailbox persistence.

                After containment:
                  1. Finance callback on payment changes
                  2. Disable legacy auth
                  3. DLP / external forward controls
                  4. Role-based awareness for finance

                Technical specifics:
                - Payment-change draft after inbox rule = fraud staging
                  - External forward-all = confidentiality / collection indicator
                  - Eradication backlog: CA for risky sign-ins, forward controls, disable legacy protocols that skip MFA

                Worked example:
                Awareness-only response to confirmed BEC is incomplete. Needs technical identity/mail fixes. Opening inbound RDP 'so finance can check the server' during BEC makes the blast radius worse.

                How to answer on the exam:
                1. Reject poster-only primary answers.
                  2. Prefer revoke/remove/reset.
                  3. Add process for finance.

                Common trap: opening inbound RDP 'so finance can check the server' during BEC.

                Remember: Contain mailbox persistence first. Awareness comes after, not instead.
                """),
            ("801 indicators: deepfake and quishing cues", """
                Where you see this at work: a voicemail that sounds exactly like the CFO
                urges a same-day wire. Separately, a printed invoice QR sends phones to a
                fake login page. Separately, MFA push spam hits a laptop that also ran
                living-off-the-land PowerShell (using built-in tools, not a new malware file).

                In Security+ terms, that is expanded malicious-activity indicators on
                SY0-801: deepfake social pressure, quishing (QR phishing), MFA bypass
                attempts, and living-off-the-land (LOTL) endpoint cues.

                Indicator map add-ons:
                  1. Deepfake audio/video: verify out-of-band; do not trust voice alone
                  2. Quishing: phone hits unknown domain after scanning QR; watch MFA
                  3. MFA fatigue / bypass attempts: repeated pushes, unexpected prompts
                  4. LOTL: excel → powershell, wmic, bitsadmin without a new PE drop

                Technical specifics:
                  - Finance callback on known numbers beats voice-match confidence.
                  - Quishing pairs with SigninLogs (new device, odd geo) and URL blocks.
                  - MFA bypass smell: success after many denies, or legacy auth skipping MFA.
                  - LOTL: parent/child process trees in EDR matter more than "no AV hit."

                Worked example:
                "CEO voice" asks for gift-card codes on a weekend. No ticket, no known
                callback. Treat as social-engineering / deepfake-enabled fraud staging.
                Verify via known channel before any payment or secret share.

                How to answer on the exam:
                  1. Match the indicator class the story shows.
                  2. Prefer verify/callback for deepfake pressure.
                  3. Prefer process-tree thinking for LOTL, not file-hash only.

                Common trap: trusting a familiar voice over procedure. Near-miss: closing
                MFA spam as user error while a session succeeded from a new country.

                Remember: Deepfake and QR still need verify-and-contain habits.
                """),
        ],
        [
            _mc("CFO forward-all to Gmail, legacy auth, East EU. First fit mitigation?",
                ["Close travel FP", "Revoke sessions, remove rule, reset, escalate BEC",
                 "Only poster", "Open 3389"], 1,
                "Contain mailbox persistence.",
                "Correct. Identity + rule first; awareness later. Poster-only is the near-miss. "),
            _mc("Why legacy auth matters in this story?",
                ["It forces MFA", "It often skipped the MFA prompt attackers fear",
                 "It encrypts the forward", "It is physical"], 1,
                "Protocol bypass.",
                "Correct. Disable legacy auth as eradication, not as a nice-to-have. "),
            _mc("Payment-change email in draft after inbox rule: meaning?",
                ["Proof it is CHG-512", "Fraud staging: warn finance, treat as part of BEC",
                 "Only spam", "Ignore"], 1,
                "Business email compromise payoff.",
                "Correct. Containment includes stopping the money path. "),
            _mc("Voicemail sounds like the CFO demanding a weekend wire. Best first move?",
                ["Trust the voice match and pay", "Out-of-band verify on a known callback channel",
                 "Open inbound RDP for finance", "Disable mailbox audit logging"], 1,
                "Deepfake-enabled social pressure.",
                "Correct. Verify out-of-band. "
                "Common trap: trusting familiar voice over procedure. "
                "Remember: deepfake does not override callback."),
        ],
        [
            _qz("q_d2_07a", "External forward-all rule is primarily:",
                ["Availability of toner", "Confidentiality / collection indicator",
                 "RTO metric", "Honeypot"], 1,
                "Correct. Mail leaving the tenant is confidentiality / collection. "),
            _qz("q_d2_07b", "Best immediate BEC containment?",
                ["Wait overnight", "Revoke sessions + remove rule + reset",
                 "Open RDP", "Disable SIEM"], 1,
                "Correct. Kill persistence and sessions. Waiting overnight is the distractor. "),
            _qz("q_d2_07c", "MITRE-ish technique family for inbox rules:",
                ["Mailbox collection / email collection", "Only physical theft",
                 "Only VLAN", "Only backup"], 0,
                "Correct. Collection of mail. Stay in the collection family. "),
            _qz("q_d2_07d", "Awareness-only response to confirmed BEC is:",
                ["Complete", "Incomplete: needs technical identity/mail fixes",
                 "Better than containment", "A backout plan"], 1,
                "Correct. People + tech. Awareness alone is incomplete after confirmed BEC. "),
            _qz("q_d2_07e", "excel.exe spawning powershell.exe -enc with no new malware file is:",
                ["Proof the host is clean", "Living-off-the-land style endpoint indicator",
                 "Only a managerial poster event", "Automatic travel FP"], 1,
                "Correct. LOTL abuses built-in tools. "
                "Common trap: 'no new PE means no incident.' "
                "Remember: parent/child trees matter."),
        ],
        pbq_bec,
    )

    pbq_ps = {
        "id": "pbq_d2_ps",
        "kind": "pick",
        "title": "Encoded PowerShell next action",
        "prompt": (
            "WS-HR-03: powershell.exe -enc spawned by excel.exe. Parent Invoice.xlsm from email. "
            "No change ticket. Host still on the LAN. What next?"
        ),
        "choices": [
            {"id": "isolate", "text": "Isolate host, preserve EDR evidence, escalate, hunt mail campaign / hash"},
            {"id": "fp", "text": "Close FP: Excel is approved business software"},
            {"id": "wait", "text": "Leave online and re-check in the morning for encryption notes"},
            {"id": "rdp", "text": "Open internet RDP to watch Task Manager"},
        ],
        "answer": "isolate",
        "explain": (
            "Correct. Parent/child + encoded command + email lure = execution chain. Contain first."
            "'Excel is approved' is the classic near-miss. Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d2_08_ioc_endpoint", "d2_threats", "2.4",
        "Indicators: endpoint and malware execution", 18,
        ["EDR", "PowerShell", "Parent-Child Process", "Obfuscation"],
        [
            ("Encoded PowerShell tell", """
                Endpoint indicators show what ran on a host. Parent/child process means which program launched which child. Living-off-the-land means using trusted built-in tools for hostile work.

                Where you see this at work: WS-HR-03: excel.exe launches powershell.exe -enc from Invoice.xlsm in email. No change ticket. Host still on the LAN.

                In Security+ terms, that is malware execution / living-off-the-land indicators and host isolation.

                Endpoint IOC pack:
                  1. Suspicious parent/child (Office → script host)
                  2. -enc / encoded command (obfuscation, not encryption)
                  3. Unsigned script, odd path, egress after launch
                  4. No CHG explaining admin scripting

                Technical specifics:
                - EDR tree into the ticket. Preserve evidence.
                  - Do not decode malware on your hotspot admin laptop.
                  - First containment: isolate host / network contain.
                  - Hunt hash across mail gateway and other endpoints.
                  - Capture pack: process tree, command line, hash, user, path, network connects.
                  - Living-off-the-land children: powershell, wscript, mshta, rundll32 under Office parents.
                  - Encoding (-enc / Base64) is obfuscation. Say it. Do not call it encryption or AES confidentiality.

                Worked example:
                excel → powershell -enc from Invoice.xlsm = suspicious execution: isolate.
                'Excel is approved business software' is the classic near-miss close reason.
                Wrong first IR move: leave on LAN overnight to see if files encrypt. Watching ransomware finish is not analysis.

                                More desk clues:
                  - Capture: process tree, command line, hash, user, path, network connects.
                  - Isolate first on confirmed hostile child; then hunt the campaign hash in mail/EDR.
                  - Living-off-the-land: powershell, wscript, mshta, rundll32 as children of Office.
                  - Encoding (-enc) is obfuscation. Say it. Do not call it encryption.

                How to answer on the exam:
                1. Read parent/child, not only the child name.
                  2. Treat -enc as obfuscation/tradecraft.
                  3. Isolate before overnight 'curiosity.'
                  4. Preserve EDR export before casual reimage when analysis still matters.

                Common trap: leaving the host online to see if files encrypt by morning, or closing FP because Office is approved. Near-miss: calling Base64 -enc 'encryption.'

                Remember: Approved app ≠ approved child behavior. Isolate first.
                """),
            ("Approved app near-miss", """
                Where you see this at work: someone argues Excel is on the allow list, so the alert must be wrong.

                In Security+ terms, that is living-off-the-land: trusted binaries used for hostile children.

                Remember:
                  - Approved parents can launch malicious children
                  - Base64 -enc is not AES confidentiality
                  - Containment beats curiosity

                Technical specifics:
                - Wrong first move: leave on LAN overnight
                  - Right pack: isolate, preserve EDR, escalate, hunt campaign/hash
                  - After isolate: check mail gateway for the same attachment hash and other recipients

                Worked example:
                Wrong first IR move after confirmed -enc chain: leave on LAN to watch encryption. Watching ransomware finish is not analysis. Correct: isolate, preserve tree, hunt the campaign.

                How to answer on the exam:
                1. Reject 'approved app' as sole close reason.
                  2. Prefer isolate + hunt.
                  3. Keep encoding vs encryption straight.

                Common trap: decoding unknown -enc blobs on a production admin workstation.

                Remember: Parent/child + encoded command + email lure = execution chain.
                """),
        ],
        [
            _mc("excel.exe → powershell.exe -enc from Invoice.xlsm. Best read?",
                ["Approved Office: close FP", "Suspicious parent/child + encoded command: isolate",
                 "Proof DC already ransomware'd", "Authorized JUMP-01 scan"], 1,
                "Parent image + encoded command.",
                "Correct. Malware execution path. Isolation matches the mitigation."
                "Approved Office is the distractor."),
            _mc("Wrong first IR move after confirmed -enc chain?",
                ["Isolate and preserve", "Leave on LAN to see if files encrypt overnight",
                 "Escalate", "Pull EDR tree into ticket"], 1,
                "Containment before curiosity.",
                "Correct. Watching ransomware finish is not analysis. That choice is wrong on purpose. "),
            _mc("Why not decode -enc on your admin laptop immediately?",
                ["Because Base64 is encryption", "Preserve evidence; avoid contaminating analyst workstation",
                 "Because EDR forbids tickets", "Because CHG requires it"], 1,
                "Ops hygiene.",
                "Correct. Isolate victim, use a proper analysis path. Base64 is not encryption. "),
        ],
        [
            _qz("q_d2_08a", "Parent/child excel→powershell is valuable because:",
                ["It proves CHG", "It shows execution chain, not just a noisy script host",
                 "It opens RDP", "It sets RPO"], 1,
                "Correct. Context of launch beats a lonely powershell.exe alert. "),
            _qz("q_d2_08b", "-enc indicates:",
                ["Guaranteed AES confidentiality", "Likely obfuscation/tradecraft",
                 "Digital signature", "Physical access"], 1,
                "Correct. Encoding ≠ encryption. Keep saying that until exam day. "),
            _qz("q_d2_08c", "First containment for endpoint malware execution:",
                ["Ignore", "Isolate host / network contain", "Disable all MFA", "Delete SIEM"], 1,
                "Correct. Stop spread. Isolation is the first fit. "),
            _qz("q_d2_08d", "'Excel is approved' as close reason is:",
                ["Solid", "Near-miss: approved apps can launch malicious children",
                 "Required by ZT", "A backout"], 1,
                "Correct. Living-off-the-land. Approved parents can still be abusive. "),
        ],
        pbq_ps,
    )

    add(
        "sp_d2_09_ioc_network", "d2_threats", "2.4",
        "Indicators: network and exposure", 18,
        ["Firewall", "RDP", "Lateral Movement", "C2", "Beaconing"],
        [
            ("Exposure vs probe", """
                Network indicators tell you whether a path was open, used, or blocked. ALLOW means the firewall permitted the flow. DROP or DENY means it blocked that try.

                Where you see this at work: one firewall story is DROP bursts on TCP 445 with no internal follow-on. Another is ALLOW tcp/3389 from the internet to PROD-DC01.

                In Security+ terms, that is ALLOW versus DROP as different incident classes, plus lateral movement and C2 smells.

                Network IOC map:
                  1. Exposure: ALLOW on management ports to crown jewels
                  2. Probe: DROP/deny bursts that never get through
                  3. Lateral movement: odd admin shares / remote services after phishing
                  4. C2 / beaconing: steady odd egress, rare ports, staged binaries calling out

                Technical specifics:
                - Pair firewall with EDR and identity. Firewall alone is incomplete.
                  - ALLOW means path open or used. DROP means perimeter held for that try.
                  - Internet RDP to a DC is critical exposure even with no CVE string.
                  - Ports to know: 3389 RDP, 22 SSH, 445 SMB, 53 DNS, 443 HTTPS, VPN often UDP 500/4500 or TLS VPN.
                  - Beaconing: regular callback rhythm to a rare destination/port after a phishing or macro event.
                  - Do not open more inbound management ports to 'investigate live.'

                Worked example:
                Internet SMB 445 DROP, no lateral = commodity probe; note IOC.
                ALLOW 3389 to PROD-DC01 = critical exposure / investigate and remove.
                Auth from HR PC to DC admin shares after phishing = possible lateral movement. Corroborate with EDR and identity before closing as noise.

                                More desk clues:
                  - Ports: 3389 RDP, 22 SSH, 445 SMB, VPN often UDP 500/4500 or TLS VPN.
                  - Beaconing: regular callback rhythm to a rare destination after phishing/macro.
                  - Pair ALLOW rows with VPN user mapping and EDR when asset tier is high.
                  - Never open more inbound management ports to "investigate live."

                How to answer on the exam:
                1. Read ALLOW vs DROP first.
                  2. Check asset tier.
                  3. Corroborate with host/identity.
                  4. Match urgency to path, not to row count.

                Common trap: paging DROP noise like domain compromise, or treating ALLOW 3389 as INFO because volume is low. Near-miss: firewall-only forever with no host context on a lateral-looking path.

                Remember: ALLOW means path open or used; DROP means perimeter held.
                """),
            ("Lateral and C2 smells", """
                Where you see this at work: after a phishing click, WS-HR-03 suddenly authenticates to PROD-DC01 admin shares, or a new binary beacons every five minutes to a rare port.

                In Security+ terms, that is lateral movement and command-and-control (C2) network indicators.

                Hunt beats:
                  1. New east-west admin traffic after phishing
                  2. Steady callback rhythm (beaconing)
                  3. Escalate and contain the host path

                Technical specifics:
                - Best pairing: firewall + EDR/identity context
                  - Do not open more ports to 'investigate live'
                  - VPN user mapping helps tie remote ALLOW rows to a person
                  - DNS query names beside rare egress often explain the C2 smell

                Worked example:
                Beaconing ≈ steady suspicious egress / callback pattern.
                Internet RDP to DC with no VPN = critical network exposure indicator.
                One successful path to a crown jewel beats a thousand DROPs on noise.

                How to answer on the exam:
                1. Name exposure vs probe vs lateral vs C2.
                  2. Pick containment that matches.
                  3. Corroborate sources.

                Common trap: firewall-only forever with no host context on a lateral-looking path.

                Remember: Even one successful path to a crown jewel beats a thousand DROPs.
                """),
        ],
        [
            _mc("Internet SMB 445 DROP burst, no internal lateral. Take?",
                ["Rebuild every host", "Commodity probe; perimeter deny held: note IOC",
                 "Same urgency as ALLOW 3389 on DC", "Proof of CFO rules"], 1,
                "DROP + no lateral.",
                "Correct. Failed probe ≠ exposed RDP incident class. Do not over-page DROP noise. "),
            _mc("ALLOW 3389 from 203.0.113.88 → PROD-DC01. Severity mindset?",
                ["INFO only", "Critical exposure / likely incident path: remove and investigate",
                 "Ignore if no CVE", "Only awareness"], 1,
                "Path to crown jewel.",
                "Correct. Identity store + internet RDP is emergency architecture + IR. "),
            _mc("After phishing, auth from HR PC to DC admin shares suggests:",
                ["Normal toner alert", "Possible lateral movement: escalate and contain",
                 "Only CHG success", "Hashing"], 1,
                "Post-compromise movement.",
                "Correct. Hunt and isolate the path. That is lateral-movement thinking. "),
        ],
        [
            _qz("q_d2_09a", "Why is ALLOW worse than DROP for the same port?",
                ["Fonts", "ALLOW means the path worked or is open; DROP means perimeter held",
                 "DROP always means ransomware", "ALLOW is always CHG"], 1,
                "Correct. Outcome of the control. Exam loves ALLOW vs DROP contrast. "),
            _qz("q_d2_09b", "Beaconing is roughly:",
                ["Steady suspicious egress / callback pattern", "Only badge logs",
                 "Only AUP text", "RTO"], 0,
                "Correct. C2 rhythm. Steady odd callbacks are the smell. "),
            _qz("q_d2_09c", "Best pairing for network IOC triage:",
                ["Firewall only forever", "Firewall + EDR/identity context",
                 "Delete logs", "Open more ports"], 1,
                "Correct. Corroborate. Network alone is incomplete. "),
            _qz("q_d2_09d", "Internet RDP to DC with no VPN is:",
                ["Zero Trust success", "Critical network exposure indicator",
                 "Only a managerial poster", "Backup proof"], 1,
                "Correct. Architecture failure visible in firewall logs. "),
            _qz("q_d2_09e", "Firewall ALLOW tcp/3389 vs DROP tcp/445: which is worse as an incident class?",
                ["DROP is always worse because volume is higher",
                 "ALLOW to a crown jewel is worse: the path is open or used",
                 "They are identical forever", "Neither needs a ticket"], 1,
                "Correct. Outcome of the control matters more than row count. "
                "Common trap: paging DROP noise like domain compromise. "
                "Remember: ALLOW means path open; DROP means perimeter held."),
        ],
    )

    # 801 deeper drill: quishing/deepfake (2.5) after IOC lessons, before AI threats (2.6).
    register_d2_801_quishing_deepfake(add, _mc, _qz)

    # 801 objective 2.6 after IOC lessons, before 701-era mitigation lessons (now 4.1).
    register_d2_801_ai(add, _mc, _qz)

    add(
        "sp_d2_10_mitigate_identity", "d2_threats", "2.5",
        "Mitigations: identity and email", 18,
        ["MFA", "Conditional Access", "Legacy Auth", "DLP", "Password Policy"],
        [
            ("Match mitigation to pattern", """
                Mitigation means the control that interrupts the attack path you named. For identity and email, match the control to spray, brute force, or BEC.

                Where you see this at work: after spray you want MFA and smart lockout. After BEC you revoke sessions and disable legacy auth. You do not answer 'more dashboards' while the path stays open.

                In Security+ terms, that is identity and email mitigations matched to spray, brute, and BEC patterns.

                Mitigation map:
                  Spray → MFA, smart lockout, block bad IPs, hunt successes, password hygiene
                  BEC → revoke sessions, remove rules, disable legacy auth, DLP/external
                         forward controls, CA for risky sign-ins, finance callback
                  Malware execution → isolate host (not identity-poster theater)

                Technical specifics:
                - Purpose of MFA: stolen/guessed passwords become insufficient alone
                  - Purpose of disabling legacy auth: force modern auth that can demand MFA/CA
                  - External forward block = confidentiality / exfil mitigation
                  - Smart lockout: slow attacks while limiting collateral lockouts
                  - Conditional Access (CA): policy around identity, device, location, risk
                  - After spray: hunt successful 4624 / SigninLogs success from attacking IP
                  - Detect-only (more SIEM panels) is incomplete while legacy auth still works

                Worked example:
                Primary MFA purpose against spray: make password-only attacks fail more.
                Best BEC technical pair: disable legacy auth + block/alert external forwards.
                Leaving a malware host up to observe encryption is the wrong mitigation class (that needs isolate, not an identity poster).

                                More desk clues:
                  - After spray: hunt successful logons from the attacking IP before closing.
                  - Legacy auth often skips MFA. That is why disable-legacy pairs with BEC fixes.
                  - CA examples: require MFA for admins, block legacy, require compliant device.
                  - Detect-only panels are incomplete while the identity path stays open.

                How to answer on the exam:
                1. Name the pattern.
                  2. Pick the mitigation that closes that path.
                  3. Prefer purpose language over brand names.
                  4. Prefer prevent/correct before detect-only when the path is open.

                Common trap: awareness poster only for open RDP, or detect-only answers when the question asks to mitigate. Near-miss: picking MFA branding without saying what it stops.

                Remember: Purpose first, brand name second. Close the path.
                """),
            ("801 email auth: SPF, DKIM, DMARC, BIMI", """
                Where you see this at work: spoofed vendor mail passes into finance because
                the real domain has no DMARC policy. You publish SPF, DKIM, and DMARC, then
                watch aggregate reports before enforcing reject.

                In Security+ terms, that is email authentication mitigations under SY0-801
                objective 4.1 (mitigating controls moved here from older Domain 2 lists).

                Define before use:
                  - SPF (Sender Policy Framework): DNS list of hosts allowed to send for a domain
                  - DKIM (DomainKeys Identified Mail): cryptographic signature on the message
                  - DMARC (Domain-based Message Authentication, Reporting, and Conformance):
                    policy that tells receivers what to do when SPF/DKIM fail, plus reporting
                  - BIMI (Brand Indicators for Message Identification): brand logo display that
                    generally expects strong DMARC; it is not a substitute for DMARC enforce

                Technical specifics:
                  - Start with DMARC p=none + reporting, then move to quarantine/reject.
                  - SPF too many lookups or missing includes breaks legitimate mail.
                  - DKIM selectors must stay valid when keys rotate.
                  - BIMI without enforce-mode DMARC is marketing theater, not the primary control.
                  - Pair with DLP/external forward controls and legacy-auth disable for BEC.

                Worked example:
                Spoofed "accounts payable" mail uses your domain lookalike or direct spoof.
                Best mitigation class: publish and enforce SPF/DKIM/DMARC, then train finance
                on callback. Detect-only SIEM panels without DNS auth leave the spoof path open.

                How to answer on the exam:
                  1. Match spoofing stories to SPF/DKIM/DMARC purpose language.
                  2. Do not pick BIMI as the only fix for spoofed payment mail.
                  3. Keep identity containment (revoke/reset) when a mailbox is already owned.

                Common trap: treating a logo (BIMI) as proof of authenticity without DMARC.
                Near-miss: "more phishing posters" while DMARC stays unset.

                Remember: SPF says who may send. DKIM signs. DMARC enforces. BIMI brands.
                """),
        ],
        [
            _mc("Primary mitigation purpose of MFA against spray?",
                ["Faster RDP", "Make stolen/guessed passwords insufficient alone",
                 "Delete accounting", "Replace backups"], 1,
                "Second factor.",
                "Correct. MFA raises the cost of password-only attacks. That is the purpose. "),
            _mc("Best technical mitigation pair for BEC forward rules?",
                ["Only posters", "Disable legacy auth + block/alert external forwards (DLP/CA)",
                 "Open 3389", "Turn off mailbox audit"], 1,
                "Close the protocol and the exfil feature.",
                "Correct. Tech + process. Poster-only fails weekly. "),
            _mc("Mitigation that does NOT fit confirmed malware execution?",
                ["Isolate host", "Leave host up to observe encryption",
                 "Hunt hash in mail", "ASR Office→script"], 1,
                "Containment is the fit.",
                "Correct. Observation without isolate is the wrong mitigation. That choice"
                "is intentionally the bad one."),
            _mc("Best primary control against direct domain spoof into finance?",
                ["BIMI logo only with no DMARC policy", "SPF + DKIM + DMARC toward enforce",
                 "Open more SMTP relays", "Disable mailbox audit"], 1,
                "Email authentication stack.",
                "Correct. DMARC with SPF/DKIM is the spoof mitigation. "
                "Common trap: BIMI alone. Remember: enforce policy, not just logos."),
        ],
        [
            _qz("q_d2_10a", "Purpose of disabling legacy auth:",
                ["Speed toner alerts", "Force modern auth paths that support MFA/CA",
                 "Open RDP", "Remove SIEM"], 1,
                "Correct. Close weak protocols so MFA/CA can actually apply. "),
            _qz("q_d2_10b", "External forward block is mainly:",
                ["Availability of Wi-Fi", "Data exfil / confidentiality mitigation",
                 "Physical cage", "RPO number"], 1,
                "Correct. Stop mail leaving. Confidentiality mitigation. "),
            _qz("q_d2_10c", "Smart lockout purpose:",
                ["Punish users only", "Slow spray/brute while limiting collateral",
                 "Disable EDR", "Replace IR"], 1,
                "Correct. Rate-limit attacks without turning the org into a denial of service. "),
            _qz("q_d2_10d", "Picking 'awareness poster only' for open RDP is:",
                ["Correct primary mitigation", "Wrong: remove the exposure",
                 "Required ZT", "A hash"], 1,
                "Correct. Match control to vector. Open RDP needs path removal. "),
            _qz("q_d2_10e", "DMARC's main job in the email stack is:",
                ["Replace EDR on laptops", "Tell receivers how to handle SPF/DKIM failures",
                 "Open inbound RDP safely", "Disable DNS entirely"], 1,
                "Correct. DMARC is policy plus reporting on auth failures. "
                "Common trap: confusing DMARC with endpoint antivirus. "
                "Remember: DMARC enforces sender authentication outcomes."),
        ],
    )

    add(
        "sp_d2_11_mitigate_segment", "d2_threats", "2.5",
        "Mitigations: segmentation, hardening, monitoring", 18,
        ["Segmentation", "Hardening", "Isolation", "EDR", "Patching"],
        [
            ("Enterprise mitigations that show up in Boundry", """
                Beyond identity, you mitigate with segmentation, hardening, patching, isolation, and monitoring. Segmentation separates trust tiers so one breach does not freely reach everything.

                Where you see this at work: you remove internet RDP, put admins on a jump host, turn on ASR so Office cannot launch script hosts, patch the VPN client, and isolate a host that already ran malware. SIEM still watches, but watching alone is not enough.

                In Security+ terms, that is segmentation, hardening, patching, isolation, and monitoring as mitigation classes.

                Purpose map:
                  Segmentation / deny 3389: shrink blast radius, remove exposure
                  Hardening / ASR: stop Office → script hosts
                  Patching: reduce exploitability of known vulns
                  Isolation: corrective containment after execution
                  Monitoring (SIEM/EDR): detective layer; necessary, not sufficient alone

                Technical specifics:
                - Exposed RDP → remove path / VPN+PAM (not another dashboard)
                  - Macro malware → ASR + mail controls + isolate if already running
                  - Unpatched VPN → patch/replace, then monitor
                  - Monitoring without removing open 3389 = detective coverage on an
                    unfixed preventive failure
                  - Jump / PAM: broker admin access; deny user VLANs to DC admin ports by default
                  - Isolation timing: after suspected/confirmed execution, not instead of never writing tickets

                Worked example:
                Best mitigation for internet RDP to DC: remove internet RDP; VPN+MFA+jump/PAM; segment.
                Purpose of isolation after malware: corrective stop-spread.
                ASR blocking Office→child script = hardening / preventive endpoint mitigation.
                Near-miss: more SIEM panels as the primary fix for internet RDP to a DC.

                                More desk clues:
                  - Jump/PAM brokers admin; deny user VLANs to DC admin ports by default.
                  - Isolation timing: after suspected/confirmed execution on the host.
                  - Patching removes known exploitability; segmentation removes free blast radius.
                  - Monitoring without removing open 3389 is detective coverage on a preventive miss.

                How to answer on the exam:
                1. Identify the open path or failed host.
                  2. Prefer cheapest reliable interrupt, preferably before execution.
                  3. Do not confuse detect with prevent.

                Common trap: more SIEM panels as the primary fix for internet RDP to a DC.

                Remember: Interrupt the kill chain at the cheapest reliable step.
                """),
            ("Pick the fit", """
                Where you see this at work: question offers four mitigations; only one matches the failure class.

                In Security+ terms, that is matching mitigation class to failure class under time pressure.

                Quick fit:
                  Path open → remove / segment
                  Code ran → isolate
                  Known vuln → patch
                  Need visibility → monitor (plus a preventive fix if path is open)

                Technical specifics:
                - Isolation timing: after suspected/confirmed execution
                  - Segmentation purpose: limit blast radius / separate trust tiers
                  - Patching purpose: remove known exploitable weakness after discover
                  - Hardening purpose: shrink attack surface before the alert fires

                Worked example:
                When is isolation the right mitigation? After suspected/confirmed execution on a host, not instead of tickets forever.
                When is segmentation right? When the question shows free east-west or internet management paths to crown jewels.

                How to answer on the exam:
                1. Name failure class.
                  2. Eliminate wrong-timing answers.
                  3. Choose path-closing control when asked to mitigate exposure.

                Common trap: using isolation as a substitute for never writing tickets or never patching.

                Remember: Detect ≠ prevent. Architecture fixes beat detective-only.
                """),
            ("801 stack: EDR/XDR, deception, WIPS", """
                Where you see this at work: EDR isolates WS-HR-03 after Office→PowerShell.
                XDR correlates that host with a suspicious Entra sign-in and a firewall ALLOW.
                A honeyfile on a finance share alerts when ransomware staging touches it.
                A canary account with no legitimate use fires on first logon. WIPS flags a
                rogue access point in the lobby.

                In Security+ terms, that is SY0-801 mitigating controls: endpoint detection
                and response (EDR), extended detection and response (XDR), deception
                (honeypot, honeynet, honeyfile, honeytoken, canary account), and wireless
                intrusion prevention (WIPS), alongside segmentation and hardening.

                Define before use:
                  - EDR: endpoint agent that detects, investigates, and responds on hosts
                  - XDR: correlates across endpoint, identity, email, and/or network signals
                  - Honeypot / honeynet: decoy system or network meant to attract attackers
                  - Honeyfile / honeytoken / canary account: decoy data or identity that
                    should never be touched in normal work; touch = high-fidelity alert
                  - WIPS: wireless intrusion prevention that can detect/block rogue WLAN threats

                Technical specifics:
                  - EDR isolate is corrective after execution; ASR is preventive before it.
                  - XDR value is correlation, not a magic auto-close. Still ticket and verify.
                  - Deception alerts are usually high confidence; still check for admin mistakes.
                  - WIPS pairs with wired NAC/802.1X stories for rogue devices.
                  - SELinux / strong OS MAC policies appear as OS hardening on the outline;
                    treat them as confinement, not a substitute for patching.

                Worked example:
                Ransomware staging opens \\finance\AP\passwords.txt.bak (a planted honeyfile).
                Alert fires before encryption notes. Best class: deception / honeyfile detection
                leading to isolate and identity hunt. Near-miss: "delete the share and hope."

                How to answer on the exam:
                  1. Match tool class to the failure (host vs wireless vs decoy).
                  2. Prefer EDR/XDR answers that include response, not only pretty graphs.
                  3. Treat canary/honey hits as investigate-now, not ignore-as-noise.

                Common trap: calling a honeypot the primary fix for internet RDP to a DC
                (remove the path first). Near-miss: XDR dashboard without isolation when
                malware already ran.

                Remember: EDR/XDR respond. Deception detects touch. WIPS watches wireless.
                """),
        ],
        [
            _mc("Best mitigation for internet RDP to DC?",
                ["More SIEM panels only", "Remove internet RDP; VPN+MFA+jump/PAM; segment",
                 "Move DC to HR Wi-Fi", "Disable logging"], 1,
                "Path removal.",
                "Correct. Architecture fix beats detective-only. Dashboards alone fail. "),
            _mc("Purpose of host isolation after malware execution?",
                ["Punish the user", "Corrective: stop spread / reduce impact",
                 "Replace MFA", "Approve CHG"], 1,
                "Containment.",
                "Correct. Isolation is corrective mitigation. Timing is after execution. "),
            _mc("Monitoring without removing open 3389 means:",
                ["Fully mitigated", "Detective coverage on an unfixed preventive failure",
                 "Physical fix", "Encryption complete"], 1,
                "Detect ≠ prevent.",
                "Correct. You still need the preventive fix. Exam loves detect-vs-prevent. "),
            _mc("Finance honeyfile opens and alerts before encryption notes. Best class?",
                ["Ignore as printer noise", "Deception detection; hunt and contain now",
                 "Proof DMARC alone is enough", "Only a directive AUP success"], 1,
                "Honeyfile / canary-style deception.",
                "Correct. Touching decoy data is a high-signal cue. "
                "Common trap: treating honey alerts as junk. "
                "Remember: deception detects unauthorized touch."),
        ],
        [
            _qz("q_d2_11a", "Segmentation purpose:",
                ["Pretty VLANs only", "Limit blast radius / separate trust tiers",
                 "Delete logs", "Disable MFA"], 1,
                "Correct. Contain movement. Pretty diagrams without policy are not enough. "),
            _qz("q_d2_11b", "ASR blocking Office→child script is:",
                ["Hardening / preventive endpoint mitigation", "Only managerial poster",
                 "RTO", "Honeypot"], 0,
                "Correct. Stop living-off-the-land before the script runs. "),
            _qz("q_d2_11c", "Patching purpose:",
                ["Remove known exploit paths", "Open more ports", "Replace IR docs", "Shame users"], 0,
                "Correct. Reduce the vulnerability window. "),
            _qz("q_d2_11d", "When is isolation the right mitigation?",
                ["Before any alert ever", "After suspected/confirmed execution on a host",
                 "Instead of tickets forever", "Only for printers"], 1,
                "Correct. Corrective timing. Isolate after execution evidence, not instead of process. "),
            _qz("q_d2_11e", "XDR compared with single-host EDR mainly adds:",
                ["A prettier laptop wallpaper", "Cross-signal correlation across tools/domains",
                 "Automatic open RDP for vendors", "Removal of the need for tickets"], 1,
                "Correct. XDR extends correlation beyond one endpoint. "
                "Common trap: treating XDR as 'no human needed.' "
                "Remember: correlate, then still verify and ticket."),
        ],
    )
