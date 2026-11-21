"""SY0-801 deeper Domain 4 mini-lessons (high-yield drills beyond baseline coverage).

Voice: .cursor/rules/tutor-professor-voice.mdc
Depth: Option 1 ~15–20 min Show-me; work picture + In Security+ terms + technical specifics.
Original Boundry content only. Official objective IDs as outline. Never dumps.
"""
from __future__ import annotations


def register_d4_801_bimi_email_auth(add, _mc, _qz) -> None:
    """801 deeper drill: BIMI + full email-auth stack (objective 4.1)."""
    add(
        "sp_d4_16_bimi_email_auth",
        "d4_operations",
        "4.1",
        "BIMI and the email authentication stack",
        18,
        [
            "SPF",
            "DKIM",
            "DMARC",
            "BIMI",
            "Email Authentication",
            "Spoofing",
            "Enforce Policy",
            "Alignment",
        ],
        [
            (
                "Logos are not the control. The stack is.",
                """
                You are studying for CompTIA Security+. CompTIA is the company that writes
                the certification. Security+ is their entry-level cybersecurity exam. The
                version these Boundry lessons target is labeled SY0-801 (say
                "S-Y-zero-eight-oh-one"). In these lessons, when I say "the exam," I mean
                Security+. A wrong answer that looks almost right is called a distractor.

                This lesson is Domain 4, objective 4.1: apply mitigating controls. Email
                authentication is how receiving servers decide whether a message that claims
                to be from your domain is allowed to look like it came from you. You already
                met SPF, DKIM, and DMARC in shorter form. Here we go deeper, including BIMI.

                SPF (Sender Policy Framework) is a DNS record listing which servers may send
                mail for a domain. DKIM (DomainKeys Identified Mail) is a cryptographic
                signature on the message. DMARC (Domain-based Message Authentication,
                Reporting, and Conformance) is a policy that tells receivers what to do when
                SPF/DKIM checks fail alignment, and it adds reporting. BIMI (Brand Indicators
                for Message Identification) is a way to show a brand logo in supporting
                inboxes when authentication is strong enough. Alignment means the domain the
                user sees matches the domain that passed SPF or DKIM in the way DMARC requires.

                Where you see this at work: finance keeps getting "CEO wire" mail from a
                lookalike domain. Your DNS shows SPF softfail only, DKIM missing on the
                marketing ESP, and DMARC at p=none. Marketing wants a shiny logo via BIMI
                before anyone moves DMARC to quarantine or reject.

                In Security+ terms, that is applying the email security stack as a mitigation:
                SPF + DKIM + DMARC toward enforce, with BIMI as a branding layer that depends
                on real authentication, not a substitute for it.

                Stack map (order of usefulness on the desk):
                  1. Inventory senders (Google, Microsoft, marketing ESP, ticketing, scanners)
                  2. SPF covers authorized IPs/includes without exploding the lookup limit
                  3. DKIM signs every legitimate stream with rotated keys
                  4. DMARC starts at monitor (p=none) with rua reports, then quarantine/reject
                  5. Fix alignment failures before you tighten policy
                  6. BIMI only after DMARC is at a strong enforcement posture (and other BIMI
                     requirements your provider documents)

                Technical specifics:
                  - SPF result alone is not DMARC pass. DMARC cares about alignment.
                  - DKIM survives some forwarding better than SPF. Forwarding breaks are a
                    common reason teams stall on enforce mode.
                  - p=none means "watch and report." It does not stop spoofed display mail.
                  - p=quarantine / p=reject are the policies that actually change attacker
                    success rates for domain spoofing.
                  - BIMI without enforce-mode DMARC is marketing theater. A logo is not proof
                    the payment request is legitimate.
                  - Lookalike domains (rn vs m, unicode tricks) may still pass their OWN
                    authentication. DMARC on YOUR domain does not stop a neighbor domain.
                    Pair with user training, banners, and vendor-payment dual control.
                  - Reports (rua/ruf): use them to find forgotten senders before you reject.
                  - Mitigations that pair with the stack: external mail banners, MTA-STS /
                    TLS reporting where used, blocking legacy protocols that skip modern
                    checks, DLP on wire-change language.

                Worked example:
                Ticket: "Enable BIMI this week so users trust our invoices." DNS shows DMARC
                p=none and two ESPs without DKIM.
                  - Wrong: publish BIMI and call email risk closed
                  - Right: finish DKIM on every stream, read DMARC aggregate reports, move
                    toward quarantine/reject, then consider BIMI
                  - If spoofed mail already uses a lookalike domain, add finance callback and
                    display-name controls even after your DMARC is perfect

                How to answer on the exam:
                  1. Ask which layer the question is testing (authorize, sign, policy, logo).
                  2. Prefer SPF+DKIM+DMARC enforce over logo-only answers.
                  3. Treat p=none as visibility, not prevention.
                  4. Remember lookalikes are a different domain problem.
                  5. BIMI is the last mile for brand display, not the first control you pick.

                Common trap: picking BIMI as the fix for spoofed CEO fraud when DMARC is still
                monitor-only. Near-miss: "SPF pass alone means the mail is safe forever."

                Remember: SPF says who may send. DKIM signs. DMARC enforces. BIMI brands
                after the first three are real.
                """,
            ),
            (
                "Tighten mail auth without breaking the business",
                """
                Where you see this at work: DMARC reports show 12% of "failing" volume is your
                own ticket system. Marketing's ESP rotates IPs weekly. Legal wants reject mode
                yesterday after a public spoof.

                In Security+ terms, that is staged email authentication hardening: discover
                senders, align SPF/DKIM, then enforce DMARC, then optional BIMI.

                Ops beats:
                  1. Freeze a sender inventory with owners.
                  2. Fix DKIM on high-volume streams first.
                  3. Keep SPF includes lean; watch the ten-lookup limit.
                  4. Move DMARC p=none → quarantine → reject with a rollback plan.
                  5. Only then evaluate BIMI / brand indicators with your mailbox providers.

                Technical specifics:
                  - Quarantine is a safer intermediate than jumping straight to reject when
                    you still have unknown senders.
                  - Subdomains may need their own DMARC policy. Attackers love forgotten
                    staging.example.com.
                  - Third-party senders: either they DKIM-sign as you (alignment) or you
                    accept they will fail when you enforce.
                  - Exam contrast: content filter / secure email gateway catches many lures;
                    authentication stops unauthorized use of YOUR domain identity. You often
                    need both.

                Worked example:
                Question shows spoofed mail From: invoices@yourdomain.com and asks for the
                control that best stops unauthorized use of that domain. Best class: DMARC
                toward reject with SPF/DKIM alignment, not "add a BIMI logo."

                How to answer on the exam:
                  1. Underline whether the attacker used your domain or a lookalike.
                  2. If your domain, push authentication enforce.
                  3. If lookalike, push user/process controls plus monitoring.
                  4. Reject logo-only comfort answers.

                Common trap: disabling SPF to "fix forwarding" instead of using DKIM and
                careful DMARC design. Near-miss: treating BIMI as encryption of email body.

                Remember: Enforce first. Brand second. Inventory always.
                """,
            ),
        ],
        [
            _mc(
                "Marketing wants BIMI logos while DMARC is still p=none. Best security answer?",
                [
                    "Publish BIMI now; logos prove authenticity alone",
                    "Finish SPF/DKIM alignment and move DMARC toward enforce first",
                    "Delete all SPF records so BIMI can activate faster",
                    "Open inbound RDP so marketing can test mailbox themes",
                ],
                1,
                "BIMI follows real DMARC enforcement.",
                "Correct. Brand indicators need a strong auth posture. "
                "Common trap: treating logos as the primary anti-spoof control. "
                "Remember: enforce first, brand second.",
            ),
            _mc(
                "DMARC p=none primarily gives you:",
                [
                    "Visibility and reporting without blocking spoofed mail yet",
                    "Automatic reject of every lookalike neighbor domain",
                    "Full disk encryption for all finance laptops overnight",
                    "Proof that BIMI logos are already phishing-proof",
                ],
                0,
                "Monitor mode is not prevention.",
                "Correct. p=none watches and reports. "
                "Common trap: calling monitor mode an enforce control. "
                "Remember: quarantine/reject change attacker success.",
            ),
            _mc(
                "Spoofed mail uses invoices@yourdomain.com. Which control class best fits?",
                [
                    "SPF, DKIM, and DMARC toward reject for your domain",
                    "BIMI logo upload with no authentication changes",
                    "Disable mailbox audit so users stop reporting phishing",
                    "Set RTO numbers without testing a restore path",
                ],
                0,
                "Unauthorized use of your domain → auth stack.",
                "Correct. Authentication enforcement stops domain spoofing. "
                "Common trap: logo-only or unrelated recovery metrics. "
                "Remember: your domain spoof needs DMARC muscle.",
            ),
        ],
        [
            _qz(
                "q_d4_16a",
                "BIMI is best described as:",
                [
                    "Brand logo display that depends on strong email authentication",
                    "A replacement for SPF, DKIM, and DMARC on every domain",
                    "A firewall rule that blocks all inbound TCP port 25",
                    "A backup encryption key stored in a break-glass envelope",
                ],
                0,
                "Correct. BIMI brands authenticated mail. "
                "Common trap: treating BIMI as the whole stack. "
                "Remember: logo after auth, not instead of auth.",
            ),
            _qz(
                "q_d4_16b",
                "DKIM's main job in the stack:",
                [
                    "Cryptographically sign messages for authenticity checks",
                    "List every sending IP allowed without requiring signatures",
                    "Force MFA push approvals for every marketing newsletter",
                    "Store offline backup tapes for mail servers in cold sites",
                ],
                0,
                "Correct. DKIM is the signature layer. "
                "Common trap: mixing DKIM with SPF's sender IP list. "
                "Remember: SPF authorizes, DKIM signs.",
            ),
            _qz(
                "q_d4_16c",
                "Why lookalike domains still fool users after your DMARC reject:",
                [
                    "They authenticate as themselves, not as your domain",
                    "DMARC automatically trusts any logo that looks familiar",
                    "SPF disables itself when unicode characters appear",
                    "BIMI blocks all neighbor domains by internet standard",
                ],
                0,
                "Correct. Neighbor domains pass their own auth. "
                "Common trap: believing DMARC ends all BEC. "
                "Remember: lookalikes need process and user defenses too.",
            ),
            _qz(
                "q_d4_16d",
                "Best first step before moving DMARC to reject:",
                [
                    "Inventory senders and fix alignment using aggregate reports",
                    "Publish BIMI and hope reports become unnecessary",
                    "Remove DKIM so SPF can work without competition",
                    "Disable external mail banners to reduce user confusion",
                ],
                0,
                "Correct. Discover and align before enforce. "
                "Common trap: jumping to logos or stripping signatures. "
                "Remember: reports find forgotten senders.",
            ),
        ],
        goal=(
            "Apply the email authentication stack: SPF, DKIM, DMARC toward enforce, "
            "and BIMI only as a dependent brand layer."
        ),
        objective_exam="SY0-801",
    )


def register_d4_801_honeyfile_deception(add, _mc, _qz) -> None:
    """801 deeper drill: honeyfile / deception controls (objective 4.1)."""
    add(
        "sp_d4_17_honeyfile_deception",
        "d4_operations",
        "4.1",
        "Honeyfiles and deception controls that alert",
        18,
        [
            "Honeyfile",
            "Honeytoken",
            "Honeypot",
            "Honeynet",
            "Canary Account",
            "Deception",
            "Detective Control",
            "False Positive",
        ],
        [
            (
                "Decoys that scream when touched",
                """
                You are studying for CompTIA Security+. This lesson deepens Domain 4,
                objective 4.1 on the SY0-801 outline: mitigating controls that include
                deception and disruption technology. Deception means placing fake assets
                that real users should never need, so any touch is a high-signal alert.

                Define the family before you mix them:
                  1. Honeyfile: a decoy file (fake payroll.xlsx, fake VPN creds.txt) that
                     alerts when opened, copied, or synced
                  2. Honeytoken: a decoy secret (API key, password, fake SAS URL) that
                     alerts when used
                  3. Honeypot: a decoy system or service that looks vulnerable or interesting
                  4. Honeynet: a network of honeypots / decoy environment
                  5. Canary account: a decoy user or service identity that should never log on
                  6. Detective control: a control whose job is to notice activity (alerts),
                     not to be your only preventive wall

                Where you see this at work: you plant payroll_EXPORT_FINAL.xlsx on a finance
                share with permissions that look normal. Nobody in the approved payroll job
                opens it. At 03:11 an account that just completed a password spray opens it
                and your canary alert fires. That is earlier notice than waiting for
                ransomware encryption noise.

                In Security+ terms, that is deception technology used as a detective
                mitigation: honeyfile, honeytoken, honeypot/honeynet, and canary accounts.

                Technical specifics:
                  - Placement: put decoys where attackers look (home drives, shares labeled
                    "finance," .env examples in repos, cloud object prefixes) without
                    blocking legitimate workflows.
                  - Alerting: open, copy, ACL change, sync to USB, or token use should page
                    with asset + user + timestamp. Low volume is the point.
                  - Honeytoken use: fake AWS key in a repo triggers cloud trail alerts when
                    someone calls the API. Fake SQL connection strings trip when used.
                  - Canary account: disable interactive use expectations; alert on any
                    4624/Sign-in. Never reuse canary passwords elsewhere.
                  - Honeypot vs honeyfile: system/service vs file decoy. Questions often mix
                    these. Match the object that was touched.
                  - Disruption: some platforms poison attacker tools or slow them. Still
                    treat deception as high-signal detection first on the exam.
                  - Limits: deception does not replace patching, MFA, or segmentation. A
                    honeypot is not a firewall. False comfort is the failure mode.
                  - Ops hygiene: document decoys so IR does not "clean up" them as malware
                    samples incorrectly, and so legitimate scanners can be allow-listed.

                Worked example:
                Alert: honeyfile "M&A_secret_valuations.xlsx" opened by svc_print on a
                workstation that also phones a rare domain.
                  - Class: deception detective hit, likely hands-on or malware search
                  - Next: isolate/investigate that host and identity, do not only delete the
                    honeyfile
                  - Contrast: a honeypot SSH listener getting internet scans may be noisy
                    commodity; prioritize based on whether the actor pivoted inside

                How to answer on the exam:
                  1. Identify which decoy object the story used (file, token, host, account).
                  2. Treat unexpected interaction as a detective signal, not proof of full
                     breach by itself.
                  3. Prefer answers that investigate the actor touching the decoy.
                  4. Reject "deploy only honeypots instead of MFA/patching."

                Common trap: calling a honeypot a preventive control that stops all attacks,
                or planting decoy secrets in places users must open daily (alert fatigue).

                Remember: Real work should never need the decoy. Touch equals ticket.
                """,
            ),
            (
                "Pick the right decoy for the path you fear",
                """
                Where you see this at work: you fear credential theft from repos, share
                browsing after phishing, and quiet service-account abuse. One honeypot VM
                on the DMZ will not cover all three.

                In Security+ terms, that is matching deception controls to the attack path:
                honeyfile for share snooping, honeytoken for secret use, canary account for
                identity abuse, honeypot/honeynet for service interaction.

                Match table:
                  Attacker searches file shares → honeyfile
                  Attacker steals keys from git → honeytoken
                  Attacker tries dormant admin → canary / decoy account
                  Attacker scans fake vulnerable app → honeypot
                  Attacker wanders a fake segment → honeynet

                Technical specifics:
                  - Cloud: decoy storage objects, decoy IAM users, decoy functions. Same
                    idea, different console.
                  - Endpoint: decoy files with kernel/EDR callbacks when read.
                  - Identity: canary users with alerting Conditional Access / impossible
                    travel rules already attached.
                  - Tuning: exclude backup crawlers and AV if they generate known opens.
                    Document exceptions. Do not silence the alert class entirely.
                  - Evidence: deception alerts are great IR breadcrumbs. Preserve host and
                    identity timeline around the first touch.

                Worked example:
                Exam ask: which control best detects an insider browsing sensitive shares
                without exfil malware? Strong answer: honeyfile/canary document on that
                share with open alerts. Weaker: "buy another firewall" with no detective
                placement on the share path.

                How to answer on the exam:
                  1. Name the asset class at risk (file, secret, account, service).
                  2. Pick the matching decoy.
                  3. Keep preventive controls in the story when the question asks to stop
                     a path, not only detect it.

                Common trap: equating any deception hit with "immediate ransomware
                confirmed" without corroboration. Near-miss: putting production data inside
                a "honeypot" and calling it safe.

                Remember: Decoy type follows attacker curiosity. Alert early, then prove.
                """,
            ),
        ],
        [
            _mc(
                "A decoy payroll.xlsx alerts when a sprayed account opens it. What control is that?",
                [
                    "Honeyfile detective deception on a share",
                    "Preventive firewall deny that blocks all SMB forever",
                    "Directive policy text with no technical monitoring",
                    "Corrective restore from backup without investigation",
                ],
                0,
                "Decoy file touch = honeyfile signal.",
                "Correct. Honeyfiles alert when touched. "
                "Common trap: calling every decoy a preventive firewall. "
                "Remember: touch equals ticket.",
            ),
            _mc(
                "A fake cloud API key in a public repo triggers when someone calls the API. Best label?",
                [
                    "Honeytoken detecting use of a decoy secret",
                    "Honeynet spanning three fake VLANs only",
                    "Passkey registration for passwordless staff login",
                    "DMARC reject policy for the marketing domain",
                ],
                0,
                "Decoy secret use = honeytoken.",
                "Correct. Honeytokens are credentials that should never be used. "
                "Common trap: mixing tokens with network honeynets. "
                "Remember: secret use is the signal.",
            ),
            _mc(
                "Best use of deception alongside real hardening?",
                [
                    "High-signal detection while MFA, patching, and segmentation still run",
                    "Replace all preventive controls with a single internet honeypot",
                    "Store crown-jewel payroll inside the honeypot for realism",
                    "Disable logging on canary accounts to reduce noise permanently",
                ],
                0,
                "Deception complements, not replaces, prevention.",
                "Correct. Decoys detect; hardening still blocks paths. "
                "Common trap: honeypot-as-entire-strategy. "
                "Remember: decoys are detective spice, not the meal.",
            ),
        ],
        [
            _qz(
                "q_d4_17a",
                "A canary account should:",
                [
                    "Never be used for real work; any sign-in is an alert",
                    "Be the daily shared admin login for the helpdesk team",
                    "Hold production payroll files as its home directory",
                    "Disable all SIEM rules attached to its object ID",
                ],
                0,
                "Correct. Canaries are decoy identities. "
                "Common trap: using them as shared admins. "
                "Remember: real work never needs the canary.",
            ),
            _qz(
                "q_d4_17b",
                "Honeypot vs honeyfile — clearest difference:",
                [
                    "Honeypot is a decoy system/service; honeyfile is a decoy file",
                    "Honeypot encrypts disks; honeyfile replaces DMARC",
                    "Honeyfile blocks ransomware; honeypot only stores logos",
                    "They are identical terms with no operational difference",
                ],
                0,
                "Correct. Object type differs. "
                "Common trap: using the words interchangeably on the exam. "
                "Remember: host vs file decoy.",
            ),
            _qz(
                "q_d4_17c",
                "After a honeyfile open alert, best next analyst move:",
                [
                    "Investigate the user/host that touched it and corroborate activity",
                    "Delete the alert and the decoy so dashboards stay green",
                    "Open inbound RDP to interview the attacker interactively",
                    "Disable EDR on that host to calm follow-on detections",
                ],
                0,
                "Correct. The touch is a lead to investigate. "
                "Common trap: erasing evidence to quiet the queue. "
                "Remember: decoy hit starts triage, not file deletion theater.",
            ),
            _qz(
                "q_d4_17d",
                "Deception controls are primarily which control function?",
                [
                    "Detective: they notice interaction with decoy assets",
                    "Preventive encryption of every packet on the WAN",
                    "Directive posters that replace technical alerting",
                    "Compensating physical locks for missing patching forever",
                ],
                0,
                "Correct. Deception is high-signal detection. "
                "Common trap: calling honeypots pure prevention. "
                "Remember: function is notice, then respond.",
            ),
        ],
        goal=(
            "Apply deception mitigations: honeyfile, honeytoken, honeypot/honeynet, and "
            "canary accounts as high-signal detective controls."
        ),
        objective_exam="SY0-801",
    )


def register_d4_801_cspm_bug_bounty(add, _mc, _qz) -> None:
    """801 deeper drill: CSPM + bounty / responsible disclosure (objective 4.3)."""
    add(
        "sp_d4_18_cspm_bug_bounty",
        "d4_operations",
        "4.3",
        "CSPM posture findings and bug bounty intake",
        18,
        [
            "CSPM",
            "Cloud Posture",
            "Misconfiguration",
            "Bug Bounty",
            "Responsible Disclosure",
            "Vulnerability Management",
            "Remediation",
            "Verification",
        ],
        [
            (
                "Cloud posture is a vuln queue, not a wallpaper dashboard",
                """
                You are studying for CompTIA Security+. This lesson deepens Domain 4,
                objective 4.3 on SY0-801: vulnerability management tasks. Besides scanners
                and CVEs, the outline calls out cloud security posture management (CSPM)
                and bounty / responsible disclosure paths.

                CSPM means tooling and process that continuously check cloud accounts for
                risky misconfigurations (public storage, open security groups, disabled
                logging, over-privileged roles). A bug bounty program pays or rewards
                outside researchers for reporting real weaknesses under rules. Responsible
                disclosure is the expected process: report privately, give time to fix, then
                coordinate publication. Neither is a free-for-all hack of production without
                scope.

                Where you see this at work: CSPM opens "storage account allows public blob
                access" on prod receipts. Same week a researcher emails security@ with a
                screenshot of an exposed staging bucket under your bounty scope. Both are
                vulnerability management work: prioritize, assign owner, remediate, verify.

                In Security+ terms, that is performing vuln management with CSPM findings
                and external disclosure/bounty intake, not only CVSS from a network scanner.

                Lifecycle beats (same loop, new inputs):
                  1. Identify (CSPM check, bounty report, pen test note, code review)
                  2. Prioritize (exposure, data class, exploitability, asset tier)
                  3. Remediate (fix config, revoke key, patch, WAF rule as temporary)
                  4. Verify (re-scan, prove public access is gone, confirm with reporter)
                  5. Report (ticket trail, metrics, exec summary when needed)

                Technical specifics:
                  - CSPM common hits: public object storage, 0.0.0.0/0 admin ports, missing
                    encryption flags, logging disabled, wildcard IAM, open Kubernetes API,
                    legacy access keys.
                  - CSPM is configuration posture. A CVE scanner finds software bugs. You
                    need both mental models. Public storage may have no CVE and still be
                    CRITICAL.
                  - Prioritize internet-exposed crown-jewel data over private sandbox noise.
                  - Bounty scope: in-scope assets, out-of-scope (DoS, social engineering of
                    staff, data destruction). Out-of-scope reports still get a polite close.
                  - Responsible disclosure intake: unique mailbox, ticket SLA, no retaliate-
                    by-default, patch-then-publish coordination.
                  - Verification: CSPM re-check + manual URL test + evidence attached.
                    "Ticket closed" without re-check is a common fail.
                  - Compensating control: temporary block/WAF while engineering removes the
                    root misconfig. Do not leave the exception forever.

                Worked example:
                CSPM CRITICAL: public bucket with invoices. Bounty report: same bucket via
                a guessed URL. Pen test PDF: medium finding on an internal wiki.
                  - Fix public bucket first (exposure + data class)
                  - Thank researcher, verify closure, pay per policy if in scope
                  - Schedule wiki issue with owner; do not let it jump the public-data queue
                    just because a PDF looks formal

                How to answer on the exam:
                  1. Classify the input (CSPM misconfig vs CVE vs bounty).
                  2. Rank by exposure and data impact.
                  3. Include verify/re-check in the remediation answer.
                  4. Treat bounty/responsible disclosure as a managed process, not ignore
                     or "hack back."

                Common trap: dismissing CSPM because "there is no CVE." Near-miss: paying a
                bounty while leaving the bucket public, or running a bounty with no scope.

                Remember: Posture findings are vulns too. Fix, prove, then thank the reporter.
                """,
            ),
            (
                "Intake without chaos: bounty meets the queue",
                """
                Where you see this at work: three researchers hit security@ on a Friday.
                One is in-scope XSS. One is out-of-scope spam. One threatens public dump in
                two hours. CSPM still shows two public snapshots.

                In Security+ terms, that is vulnerability management under external pressure:
                triage disclosure, keep scope, remediate, verify, communicate.

                Process beats:
                  1. Ack receipt; open a ticket with severity draft.
                  2. Validate: reproduce safely, confirm asset ownership and data class.
                  3. Contain if actively exposed (remove public ACL now).
                  4. Remediate root cause with change control when needed.
                  5. Verify and notify reporter; track SLA metrics.

                Technical specifics:
                  - Legal/policy: bounty terms, safe harbor for good-faith research in scope,
                    escalation path for extortionate threats (IR + leadership, not silent hope).
                  - Duplicate reports: link tickets; still verify the fix once.
                  - Cloud urgency cues: public = internet principals can read; "authenticated
                    users" broad grants can be almost as bad depending on tenant.
                  - Pair CSPM with inventory: orphan accounts and shadow subscriptions create
                    findings nobody owns. Ownership is half of remediation.
                  - Reporting: weekly posture trend (open CRITICAL age) beats screenshot
                    theater.

                Worked example:
                Exam ask: researcher finds public object storage; CSPM also flagged it
                yesterday unanswered. Best next step?
                  - Remove public access / lockdown now, assign cloud owner, verify, then
                    complete disclosure paperwork
                  - Not "wait for the next quarterly scan window" while data stays public

                How to answer on the exam:
                  1. Stop the bleed (exposure) before debate about CVSS labels.
                  2. Keep bounty communication professional and scoped.
                  3. Prefer verify steps in the answer choices.

                Common trap: treating bounty mail as spam always, or treating every researcher
                demand as an emergency that skips validation. Near-miss: "CSPM dashboard green
                means no vulns" while bounty inbox is ignored.

                Remember: Exposure first. Scope second. Proof before you close.
                """,
            ),
        ],
        [
            _mc(
                "CSPM flags public cloud storage with invoices. No CVE ID exists. Best take?",
                [
                    "Misconfiguration still prioritizes by exposure and data impact",
                    "Ignore it until a CVE number is published for storage",
                    "Close as FP because bounty programs replace CSPM forever",
                    "Open more admin ports so the bucket can be patched faster",
                ],
                0,
                "Posture issues need no CVE to be urgent.",
                "Correct. Public data exposure ranks high without a CVE. "
                "Common trap: CVE-only thinking. "
                "Remember: posture findings are vulns too.",
            ),
            _mc(
                "In-scope bounty report shows the same public bucket CSPM already opened. Best ops move?",
                [
                    "Lock down access now, verify, then complete disclosure handling",
                    "Ignore the researcher because an internal ticket already exists",
                    "Pay immediately without validating or removing public access",
                    "Disable CSPM so duplicate alerts stop embarrassing the team",
                ],
                0,
                "Contain and verify, then finish the disclosure loop.",
                "Correct. Stop exposure, prove it, communicate. "
                "Common trap: paperwork without lockdown, or lockdown without courtesy. "
                "Remember: fix and prove before you close.",
            ),
            _mc(
                "Responsible disclosure primarily expects researchers to:",
                [
                    "Report privately and allow time to fix before publishing",
                    "Dump all customer data publicly on day zero for pressure",
                    "Run destructive DoS tests on production without scope limits",
                    "Demand admin VPN access as the only valid proof method",
                ],
                0,
                "Private report + time to remediate.",
                "Correct. Responsible disclosure is coordinated and scoped. "
                "Common trap: treating extortion or destruction as normal research. "
                "Remember: private report, then fix, then publish.",
            ),
        ],
        [
            _qz(
                "q_d4_18a",
                "CSPM is best described as:",
                [
                    "Continuous checking of cloud configs for risky posture gaps",
                    "A physical cage lock around on-prem tape libraries only",
                    "A replacement for identity MFA on all human accounts",
                    "A DMARC reject policy for the corporate mail domain",
                ],
                0,
                "Correct. CSPM watches cloud posture/misconfig. "
                "Common trap: mixing it with physical or mail controls. "
                "Remember: cloud config risk, continuously.",
            ),
            _qz(
                "q_d4_18b",
                "After remediating a public bucket, verification means:",
                [
                    "Re-check CSPM/manual access tests and attach evidence",
                    "Closing the ticket the same minute the engineer says done",
                    "Paying any email that claims to be a researcher",
                    "Deleting cloud audit logs so the finding cannot recur in reports",
                ],
                0,
                "Correct. Prove the exposure is gone. "
                "Common trap: trust-me closes without re-check. "
                "Remember: verify before you celebrate.",
            ),
            _qz(
                "q_d4_18c",
                "A bug bounty program needs clear scope mainly to:",
                [
                    "Define allowed targets/tests and reject out-of-scope harm",
                    "Guarantee every spam email earns a cash payout",
                    "Authorize opening inbound RDP for all researchers globally",
                    "Disable vulnerability scanning inside the cloud accounts",
                ],
                0,
                "Correct. Scope protects researchers and the business. "
                "Common trap: unbounded testing as 'security culture.' "
                "Remember: in-scope rules make bounty safe.",
            ),
            _qz(
                "q_d4_18d",
                "Best prioritization cue for CSPM findings:",
                [
                    "Internet exposure plus sensitive data class and blast radius",
                    "Alphabetical order of subscription display names only",
                    "Whatever alert has the prettiest dashboard widget color",
                    "Findings that lack CVE IDs are always lowest priority forever",
                ],
                0,
                "Correct. Exposure and impact drive the queue. "
                "Common trap: ignoring non-CVE posture gaps. "
                "Remember: public + sensitive jumps the line.",
            ),
        ],
        goal=(
            "Perform vuln management with CSPM posture findings and bounty / responsible "
            "disclosure intake: prioritize, fix, verify, communicate."
        ),
        objective_exam="SY0-801",
    )


def register_d4_801_passkeys_jit(add, _mc, _qz) -> None:
    """801 deeper drill: passkeys / passwordless / JIT (+ light gMSA) (objective 4.5)."""
    add(
        "sp_d4_19_passkeys_jit_identity",
        "d4_operations",
        "4.5",
        "Passkeys, passwordless, and just-in-time access",
        19,
        [
            "Passkey",
            "Passwordless",
            "Just-In-Time",
            "Phishing Resistant",
            "Emergency Access",
            "gMSA",
            "Privileged Access",
            "MFA",
        ],
        [
            (
                "Stop typing secrets that attackers can relay",
                """
                You are studying for CompTIA Security+. This lesson deepens Domain 4,
                objective 4.5 on SY0-801: identity and access management concepts. You will
                focus on passkeys, passwordless authentication, just-in-time (JIT) access,
                and a short note on group Managed Service Accounts (gMSA) for service
                identity hardening.

                Definitions first:
                  1. Authentication (AuthN): proving you are the account holder
                  2. Passwordless: proving identity without typing a reusable password
                     (device biometric + cryptographic credential, hardware key, etc.)
                  3. Passkey: a phishing-resistant credential bound to a device/authenticator
                     using public-key style cryptography (often synced or device-bound)
                  4. Phishing-resistant: hard to steal via fake login pages that relay codes
                  5. Just-in-time (JIT): privileged access granted only for a short window
                     when needed, then removed
                  6. Emergency access (break-glass): rare, monitored accounts for when normal
                     admin paths fail
                  7. gMSA: a Windows Active Directory managed service account password that
                     the domain handles automatically for a group of hosts (no human-set
                     standing service password in a wiki)

                Where you see this at work: admins still approve SMS OTPs on lookalike pages.
                You move admin sign-in to passkeys or FIDO2 hardware keys. Standing Domain
                Admin is replaced with JIT elevation that expires in one hour. A legacy
                batch job stops using Password123 in a share and moves to a gMSA.

                In Security+ terms, that is applying modern IAM: passwordless/passkey AuthN,
                JIT privileged access, emergency access discipline, and hardened service
                identities.

                Technical specifics:
                  - Passkeys defeat many relay phishing kits because the authenticator checks
                    the real origin (site identity) before signing.
                  - SMS/email OTP and some push MFA are better than passwords alone but are
                    not the phishing-resistant bar passkeys/FIDO aim for.
                  - Passwordless is the pattern; passkey is a common implementation. Hardware
                    security keys are related and often appear in the same answer family.
                  - JIT: request → approve → short group membership / role activation →
                    automatic removal. Audit who approved.
                  - Standing privilege is the enemy. "Always Global Admin" fails this lesson.
                  - Emergency access: offline cached credentials or break-glass accounts,
                    monitored, dual control, not used for daily tickets.
                  - gMSA (identity hardening beat): services get automatically rotated
                    passwords managed by AD; reduces shared service-account passwords and
                    privilege creep from sticky wiki secrets. Pair with least privilege on
                    what the service can do. (Architecture objective 3.2 also mentions gMSA;
                    here you care about the IAM ops outcome.)
                  - Lifecycle still matters: joiner/mover/leaver, access reviews, disable on
                    termination day.

                Worked example:
                BEC kit phishes an admin OTP. After incident: require phishing-resistant
                passkey for privileged roles, remove standing admin, enable JIT for elevation,
                monitor break-glass, convert the backup service from a shared password to
                gMSA where the platform supports it.
                  - Wrong answer class: "more SMS OTP" as the final privileged control
                  - Right answer class: phishing-resistant AuthN + time-bounded privilege

                How to answer on the exam:
                  1. Match passkey/passwordless to phishing-resistant authentication.
                  2. Match JIT to short-lived privilege, not permanent group adds.
                  3. Keep emergency access rare and monitored.
                  4. Treat gMSA/service managed identities as removing human-handled secrets.
                  5. Reject "disable MFA for convenience" and "shared admin forever."

                Common trap: equating any MFA with passkeys, or calling JIT the same as
                permanent role-based access that never expires.

                Remember: Passkeys resist phishing. JIT expires power. Services should not
                share wiki passwords.
                """,
            ),
            (
                "Choose the IAM control that matches the failure",
                """
                Where you see this at work: four failures. (1) Admin OTP relayed. (2) Vendor
                still in Global Admin after the project. (3) Break-glass used for daily
                Slack jokes. (4) svc_backup password in a README.

                In Security+ terms, that is pairing IAM fixes: passkey/passwordless, JIT /
                removal of standing privilege, emergency access hygiene, and managed service
                accounts (gMSA / cloud equivalent).

                Quick fit:
                  Relayed interactive phish → phishing-resistant passkey / FIDO
                  Standing admin after project → JIT + access review removal
                  Daily break-glass → stop abuse; monitor; separate emergency path
                  Wiki service password → gMSA or cloud managed identity

                Technical specifics:
                  - Conditional Access can require phishing-resistant methods for admin
                    portals while allowing weaker methods for low-risk apps during transition.
                  - JIT systems (PIM-style) create audit: who activated what, when, why.
                  - Password managers help humans; they do not replace passkeys for the
                    highest-risk admin plane.
                  - Service accounts: least privilege, no interactive logon where possible,
                    monitored use, managed secrets.

                Worked example:
                Exam ask: which control best reduces successful MFA relay against admins?
                Prefer passkey/passwordless phishing-resistant methods. Not "longer passwords
                only," not "disable MFA."

                How to answer on the exam:
                  1. Underline whether the problem is AuthN strength or privilege duration.
                  2. Pick passkey/passwordless for AuthN relay stories.
                  3. Pick JIT for standing privilege stories.
                  4. Mention monitoring when emergency access appears.

                Common trap: "JIT" answers that still leave permanent Domain Admin. Near-miss:
                using gMSA as the answer to a human phishing question.

                Remember: Strength for login. Time-box for power. Manage service secrets.
                """,
            ),
        ],
        [
            _mc(
                "Admins keep approving OTP on lookalike sites. Best AuthN upgrade?",
                [
                    "Phishing-resistant passkeys or FIDO-class passwordless methods",
                    "Longer SMS codes with the same relayable approval pattern",
                    "Shared seasonal passwords posted in the helpdesk channel",
                    "Disable MFA so users stop clicking wrong prompts entirely",
                ],
                0,
                "Passkeys resist relay phishing better than OTP.",
                "Correct. Passkeys/passwordless raise the phishing-resistant bar. "
                "Common trap: more OTP of the same weak class. "
                "Remember: origin-bound credentials beat typed codes.",
            ),
            _mc(
                "A contractor still has standing Global Admin months later. Best control pattern?",
                [
                    "Just-in-time elevation with expiry plus access review removal",
                    "Leave standing admin and add a prettier dashboard widget",
                    "Move the contractor to a canary honeyfile on a finance share",
                    "Publish BIMI logos so admin portals look more trustworthy",
                ],
                0,
                "JIT and review remove standing privilege.",
                "Correct. Time-bounded privilege beats permanent admin. "
                "Common trap: unrelated deception or email branding answers. "
                "Remember: power should expire.",
            ),
            _mc(
                "A Windows batch service uses a password in a wiki. Best identity hardening?",
                [
                    "Move it to a gMSA or managed service identity with least privilege",
                    "Print the wiki password larger so operators type it faster",
                    "Grant the service Domain Admin to avoid future permission tickets",
                    "Store the same password in three more shared mailboxes for HA",
                ],
                0,
                "Managed service accounts remove human-handled secrets.",
                "Correct. gMSA/managed identities rotate and constrain service creds. "
                "Common trap: sharing or escalating service passwords. "
                "Remember: services should not live in wikis.",
            ),
        ],
        [
            _qz(
                "q_d4_19a",
                "Compared with SMS OTP, a passkey is best described as:",
                [
                    "A phishing-resistant authenticator-bound cryptographic credential",
                    "A shared mailbox password rotated every leap year only",
                    "A firewall ANY/ANY rule for privileged admin troubleshooting",
                    "A honeypot file placed on every user desktop overnight",
                ],
                0,
                "Correct. Passkeys are cryptographic and phishing-resistant. "
                "Common trap: equating them with shared passwords. "
                "Remember: device-bound proof, not typed secrets.",
            ),
            _qz(
                "q_d4_19b",
                "Just-in-time access primarily means:",
                [
                    "Short-lived privilege granted when needed, then removed",
                    "Permanent Domain Admin for anyone who opens a ticket once",
                    "Disabling all authentication during change freezes",
                    "Replacing asset inventory with a single emergency account",
                ],
                0,
                "Correct. JIT is time-bounded elevation. "
                "Common trap: permanent privilege labeled as JIT. "
                "Remember: access that expires on purpose.",
            ),
            _qz(
                "q_d4_19c",
                "Emergency access accounts should be:",
                [
                    "Rarely used, tightly monitored, and not for daily admin work",
                    "The default login for all Tier-1 analysts every shift",
                    "Shared in cleartext inside public chat channels for speed",
                    "Excluded from logging so attackers cannot see the name",
                ],
                0,
                "Correct. Break-glass is rare and watched. "
                "Common trap: daily use of emergency paths. "
                "Remember: emergency means exceptional.",
            ),
            _qz(
                "q_d4_19d",
                "gMSA helps most with which problem?",
                [
                    "Human-handled standing passwords on Windows service accounts",
                    "Deepfake voice verification for finance wire changes",
                    "DMARC logo publishing for consumer mail clients",
                    "Choosing paint colors for the SOC room acoustic panels",
                ],
                0,
                "Correct. gMSA manages service account credentials in AD. "
                "Common trap: using gMSA as the answer to unrelated social or mail items. "
                "Remember: managed service identity, fewer wiki secrets.",
            ),
            _qz(
                "q_d4_19e",
                "Passwordless authentication means:",
                [
                    "Proving identity without typing a reusable password",
                    "Removing all authentication from admin portals permanently",
                    "Allowing blank passwords for service accounts in production",
                    "Disabling encryption so logons complete a few milliseconds faster",
                ],
                0,
                "Correct. Passwordless replaces typed passwords with stronger factors. "
                "Common trap: reading it as 'no security.' "
                "Remember: no reusable password, still strong proof.",
            ),
        ],
        goal=(
            "Apply IAM scenarios with passkeys/passwordless, JIT privilege, emergency "
            "access discipline, and managed service identities (gMSA)."
        ),
        objective_exam="SY0-801",
        legacy_ref="4.6",
    )


def register_d4_801_agentic_guardrails(add, _mc, _qz) -> None:
    """801 deeper drill: agentic AI automation + guardrails (objective 4.6)."""
    add(
        "sp_d4_20_agentic_ai_guardrails",
        "d4_operations",
        "4.6",
        "Agentic AI automation and guardrails",
        18,
        [
            "Agentic AI",
            "Chatbot",
            "Guardrails",
            "SOAR",
            "Human Gate",
            "Orchestration",
            "Least Privilege",
            "Playbook",
        ],
        [
            (
                "Bots that act need brakes",
                """
                You are studying for CompTIA Security+. This lesson deepens Domain 4,
                objective 4.6 on SY0-801: automation and orchestration. Beyond classic SOAR
                playbooks, the outline highlights AI capabilities such as chatbots and
                agentic automation. You must know what they are and how guardrails keep them
                from causing harm.

                Definitions:
                  1. Automation: software runs repeatable steps without a human each time
                  2. Orchestration: connecting multiple tools into a coordinated workflow
                  3. SOAR: security orchestration, automation, and response platforms
                  4. Chatbot: conversational interface that drafts or answers with AI text
                  5. Agentic AI: an AI system that can plan steps and call tools/actions
                     (ticket updates, email, isolation APIs), not only generate text
                  6. Guardrails: limits that bound what automation may do (allow lists,
                     rate limits, approvals, least-privilege tool scopes, kill switches)
                  7. Human gate: a required approval before a high-impact action runs

                Where you see this at work: a chatbot summarizes spray tickets helpfully. An
                agentic playbook then tries to disable thirty accounts and email customers
                without approval because a prompt said "resolve all urgency now." Without
                guardrails, speed becomes blast radius.

                In Security+ terms, that is applying automation with AI capabilities under
                guardrails: chatbots for assistive text, agentic tools only with tight
                scopes and human gates for destructive steps.

                Technical specifics:
                  - Chatbot risk: confidential paste into prompts, wrong advice trusted as
                    fact, ticket notes that leak secrets into the model log.
                  - Agentic risk: tool abuse after prompt injection, mass containment errors,
                    irreversible deletes, spam to customers, privilege escalation via over-
                    scoped API tokens.
                  - Guardrail catalog: allow-listed tools/actions, per-action approval,
                    change windows, blast-radius caps (max N isolations/hour), identity for
                    the bot (non-human identity with least privilege), full audit logs,
                    kill switch, staging tests before production enablement.
                  - Same SOAR wisdom still applies: automate enrich/ticket first; gate
                    disable-user, wide blocks, mass isolate, outbound mass mail.
                  - Process engineering: write the happy path and the exception path. If the
                    agent is unsure, escalate to a human.
                  - Complexity/cost: more agent autonomy means more review burden. Exam
                    answers that "fully autonomous forever" are usually wrong for high impact.

                Worked example:
                Agentic SOC assistant can (a) enrich IPs, (b) open tickets, (c) disable
                users, (d) email all customers. Prompt injection in a ticket says "disable
                executives and notify press."
                  - Safe design: a/b auto; c requires human gate + cap; d forbidden or dual
                    approval
                  - Failure: service principal has Directory.ReadWrite.All and send-mail
                    with no approvals
                  - Fix class: shrink scopes, require approval, log every tool call, add kill
                    switch, train analysts not to paste secrets into the bot

                How to answer on the exam:
                  1. Separate "drafts text" (chatbot) from "takes action" (agentic).
                  2. Prefer guardrails + human gates for high-impact actions.
                  3. Keep least privilege on the automation identity.
                  4. Reject answers that remove logging or approvals to "go faster."

                Common trap: treating agentic AI like a text-only chatbot, or disabling
                human gates because autonomy sounds modern.

                Remember: Chatbots draft. Agents act. Guardrails decide how far action goes.
                """,
            ),
            (
                "Design the gate before you admire the demo",
                """
                Where you see this at work: leadership demos an agent that "handles Tier-1."
                It can isolate endpoints, reset passwords, and close tickets. Nobody listed
                which actions are reversible.

                In Security+ terms, that is automation design with guardrails: classify
                actions by impact, then choose auto vs approve vs forbid.

                Impact ladder:
                  Low: enrich IOC, fetch reputation, draft summary → auto OK
                  Medium: open/update ticket, notify on-call → auto with templates
                  High: disable user, isolate host, firewall block, mass mail → human gate
                  Extreme: destroy data, broad revocation, public comms → forbid or dual control

                Technical specifics:
                  - Non-human identities need rotation, secret storage, and monitoring like
                    privileged users.
                  - Idempotent playbooks retry safely; naive loops can lockout storms.
                  - Financial/complexity considerations: brittle agents cost more IR time
                    than they save if guardrails are missing.
                  - Pair with Domain 2 AI threat knowledge: injection and jailbreak are why
                    tool scopes must stay narrow even when the demo looks perfect.

                Worked example:
                Exam ask: which control best reduces agentic damage after prompt injection?
                Prefer least-privilege tools + human approval for destructive actions +
                audit. Not "trust the model" or "disable logging."

                How to answer on the exam:
                  1. Spot whether the AI only talked or also called tools.
                  2. Pick guardrail language: allow list, approval, rate limit, kill switch.
                  3. Keep a human path for exceptions and collateral.

                Common trap: equating SOAR without AI to "no automation risk," or assuming
                chatbots cannot cause data loss via secret paste.

                Remember: Rank the action's blast radius before you grant the tool.
                """,
            ),
        ],
        [
            _mc(
                "An AI agent can disable users and send customer email without approval. Biggest gap?",
                [
                    "Missing guardrails and human gates on high-impact tools",
                    "Insufficient CVSS scoring of the chatbot font package",
                    "Lack of BIMI logos on automated notification templates",
                    "Failure to store break-glass passwords inside the model prompt",
                ],
                0,
                "High-impact tools need bounds and approvals.",
                "Correct. Agentic actions need guardrails. "
                "Common trap: unrelated branding or CVSS theater. "
                "Remember: agents act; gates bound them.",
            ),
            _mc(
                "Best first automation tier for a new SOC agent?",
                [
                    "Auto-enrich and ticket; require approval for isolate/disable",
                    "Auto-disable all executives whenever a ticket says urgent",
                    "Grant Directory-wide write and mail-send with no audit trail",
                    "Remove kill switches so the agent cannot be interrupted mid-run",
                ],
                0,
                "Start with enrich/ticket; gate containment.",
                "Correct. Low-risk automation first. "
                "Common trap: full autonomy on day one. "
                "Remember: enrich free, contain gated.",
            ),
            _mc(
                "Chatbot vs agentic AI — best distinction for the exam?",
                [
                    "Chatbots mainly draft text; agentic systems can call tools/actions",
                    "Chatbots always isolate hosts; agents only rewrite grammar",
                    "Both terms mean the same preventive firewall feature",
                    "Agentic AI cannot exist unless DMARC is at p=reject",
                ],
                0,
                "Text assist vs tool-using autonomy.",
                "Correct. Agency means actions, not only answers. "
                "Common trap: using the labels interchangeably. "
                "Remember: tools multiply blast radius.",
            ),
        ],
        [
            _qz(
                "q_d4_20a",
                "Guardrails in automation primarily:",
                [
                    "Bound what automated or agentic actions are allowed to do",
                    "Replace the need for any identity authentication forever",
                    "Guarantee that every model output is factually perfect",
                    "Disable logging so playbooks run with less storage cost",
                ],
                0,
                "Correct. Guardrails limit blast radius. "
                "Common trap: treating them as truth engines or log-off switches. "
                "Remember: bounds, approvals, least privilege.",
            ),
            _qz(
                "q_d4_20b",
                "A human gate is most appropriate when:",
                [
                    "The action is high impact or hard to reverse",
                    "The playbook only fetches a public IP reputation score",
                    "The chatbot drafts a non-binding study summary for training",
                    "The task is renaming a lab virtual machine color tag",
                ],
                0,
                "Correct. Approve destructive or broad actions. "
                "Common trap: gating harmless enrich steps only. "
                "Remember: impact drives the gate.",
            ),
            _qz(
                "q_d4_20c",
                "Least privilege for an agentic SOC bot means:",
                [
                    "Tool scopes limited to the minimum APIs the playbook needs",
                    "Global Admin on the automation account for future flexibility",
                    "Shared use of the CEO break-glass account for faster demos",
                    "Unrestricted send-mail to all customers from the service principal",
                ],
                0,
                "Correct. Shrink the bot's power to the job. "
                "Common trap: over-scoping 'just in case.' "
                "Remember: non-human identities stay least privilege.",
            ),
            _qz(
                "q_d4_20d",
                "Prompt injection against a tool-using agent is dangerous mainly because:",
                [
                    "Hostile text can trigger real actions through connected tools",
                    "It automatically raises CVSS scores on unrelated VPN appliances",
                    "It forces BIMI logos to render in every mailbox client",
                    "It converts honeyfiles into preventive firewalls by itself",
                ],
                0,
                "Correct. Injection plus tools equals action risk. "
                "Common trap: treating injection as cosmetic text only. "
                "Remember: text tricks become ticket actions.",
            ),
        ],
        goal=(
            "Apply automation with chatbots and agentic AI under guardrails: least-"
            "privilege tools, human gates, audit, and kill switches."
        ),
        objective_exam="SY0-801",
        legacy_ref="4.7",
    )


def register_d4_801_deeper_drills(add, _mc, _qz) -> None:
    """Register all SY0-801 Domain 4 deeper drills in preferred unlock-adjacent order.

    Call sites in gen_secplus_d4.d4_specs insert these beside related baseline lessons.
    This helper exists for smoke imports / explicit batch registration if needed.
    """
    register_d4_801_bimi_email_auth(add, _mc, _qz)
    register_d4_801_honeyfile_deception(add, _mc, _qz)
    register_d4_801_cspm_bug_bounty(add, _mc, _qz)
    register_d4_801_passkeys_jit(add, _mc, _qz)
    register_d4_801_agentic_guardrails(add, _mc, _qz)
