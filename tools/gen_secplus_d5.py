"""D5 lesson specs for Phase 1 generator. Program Management / Oversight.

Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).
Depth: Option 1 ~15-20 min Show-me; work-facing picture + technical specifics.
"""
from __future__ import annotations


def d5_specs(add, _mc, _qz):
    """Register Domain 5 micro-lessons (11). No PBQ: governance/vocab heavy."""

    add(
        "sp_d5_01_governance_policy", "d5_oversight", "5.1",
        "Governance: policies that mean something", 18,
        ["Security Policy", "AUP", "Standard", "Procedure"],
        [
            ("Policy stack", """
                Governance is how leadership directs and controls security. Policies state management intent. Standards give mandatory specifics. Procedures tell operators how to execute. Guidelines recommend softer practice.

                Where you see this at work: AUP says do not bypass controls. Standard says MFA required for remote admin. Procedure lists isolate-host steps. AUP alone does not stop Invoice.xlsm. Policy bans internet RDP but the firewall still shows ALLOW.

                In Security+ terms, that is policy vs standard vs procedure in a working governance stack.

                Stack:
                  Policy → intent (AUP, information security policy)
                  Standard → mandatory specifics (MFA for remote admin; no internet RDP to DCs)
                  Procedure → runnable steps (isolate, restore, offboard)
                  Guidelines → recommended, more flexible

                Technical specifics:
                - Say/do test: policy text vs live Entra / firewall / EDR config
                  - AUP without standards/procedures cannot stop macros alone
                  - Ownership and review cadence keep documents from rotting
                  - Exceptions must reference the standard they waive
                  - Effective governance shows in enforced controls, not binders
                  - Directive controls (Domain 1) often live in this stack

                Worked example:
                AUP is a directive policy. Policy says no internet RDP but ALLOW tcp/3389 to PROD-DC01 exists:
                  - Governance failure: not enforced, or uncontrolled exception
                  - Fix: remove path or written exception with owner/date/compensating control plus standard update. A signed PDF alone is not enforcement.

                                More desk clues:
                  - Say/do test: policy text vs live Entra/firewall/EDR config.
                  - AUP without standards/procedures cannot stop macros alone.
                  - Ownership and review cadence keep documents from rotting.
                  - Exceptions must reference the standard they waive.

                How to answer on the exam:
                1. Identify which document layer the question names.
                  2. Prefer enforceability answers (controls match intent).
                  3. Purpose first, product second.

                Common trap: picking a brand-name tool before naming the governance purpose. Near-miss: assuming a signed PDF equals enforcement.

                Remember: Documents mean something only when controls match written intent.
                """),
            ("Effective governance", """
                Where you see this at work: legacy auth banned in policy but still enabled in Entra.

                In Security+ terms, that is say/do gap as a governance finding.

                Effectiveness checks: ownership, review cadence, enforcement evidence, exception process.

                Technical specifics:
                - Unowned policies rot
                  - Auditors look for say/do alignment
                  - Export CA/legacy-auth config as evidence, not screenshots of a binder

                Worked example:
                Governance effectiveness shows in controls matching written intent. Disable legacy auth, evidence SigninLogs policy, assign owner.

                How to answer on the exam:
                1. Compare written rule vs live config.
                  2. Name the gap.
                  3. Assign owner.

                Common trap: assuming a signed PDF equals enforcement.

                Remember: If config disagrees with policy, governance failed until fixed or excepted.
                """),
        ],
        [
            _mc("AUP primarily is:",
                ["A firewall rule", "A directive policy telling users acceptable use",
                 "An EDR isolate", "A hot site"], 1,
                "People-facing policy.",
                "Correct. Directive managerial control. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Policy says no internet RDP but ALLOW exists. Governance status?",
                ["Success", "Failure: policy not enforced / exception uncontrolled",
                 "Only Domain 2", "Only hashing"], 1,
                "Say/do gap."),
            _mc("Procedure document for host isolate is:",
                ["How ops executes a standard/policy", "A CVE", "RPO number", "Base64"], 0,
                "Runnable steps."),
        ],
        [
            _qz("q_d5_01a", "Standard vs policy:",
                ["Identical", "Standard is more specific/mandatory detail under policy",
                 "Standard is only physical", "Policy is only PCAP"], 1,
                "Correct. Specificity. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_01b", "Governance effectiveness shows in:",
                ["Pretty binders only", "Controls matching written intent",
                 "Open 3389", "Disabled logging"], 1,
                "Correct. Enforcement. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_01c", "AUP helps after macro incidents by:",
                ["Replacing ASR", "Setting expectations + supporting awareness/HR process",
                 "Opening RDP", "Deleting SIEM"], 1,
                "Correct. People layer: still need tech. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_01d", "Unowned policies tend to:",
                ["Self-enforce", "Rot: nobody updates or audits them",
                 "Patch DCs", "Set RTO"], 1,
                "Correct. Ownership. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_01e", "Policy bans internet RDP but firewall ALLOW to the DC still exists. Best label?",
                ["Governance success because a PDF was signed",
                 "Say/do gap: written intent not enforced (or uncontrolled exception)",
                 "Automatic transfer of risk to the ISP",
                 "Proof that awareness posters are enough"], 1,
                "Correct. Compare policy text to live config. Common trap: treating a signed "
                "PDF as enforcement. Remember: documents mean something when controls match intent."),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_02_roles_exceptions", "d5_oversight", "5.1",
        "Roles, responsibilities, and exceptions", 17,
        ["RACI", "Exception", "Data Owner", "Security Committee"],
        [
            ("Who decides", """
                Roles and responsibilities clarify who owns data, systems, approvals, and exceptions. RACI is a common vocabulary: Responsible, Accountable, Consulted, Informed.

                Where you see this at work: everyone thought someone else disabled legacy auth. Vendor RDP was approved in a hallway. Nobody owned the review date. SOC can recommend; the system owner accepts residual risk.

                In Security+ terms, that is RACI-style clarity, data/system owners, and controlled exceptions.

                Role map:
                  Data owner / system owner / security lead / SOC / IT ops
                  RACI prevents 'I thought you did it'
                  Exceptions: written approval, compensating control, owner, review date

                Technical specifics:
                - Exception record fields: what, why, compensating control, approver, owner, expiry
                  - Verbal 'vendor needs it' with no expiry is how ALLOW 3389 lives forever
                  - Security committee / CAB for high-risk changes
                  - High-risk paths (internet RDP to DC) should rarely clear exception review
                  - RACI fails when Accountable is 'TBD' or 'the cloud'

                Worked example:
                Exception needs owner + compensating control + date. Hallway yes is not an exception process. If no Accountable name exists for prod DC firewall changes, governance is broken.

                                More desk clues:
                  - Exception record fields: what, why, compensating control, approver, owner, expiry.
                  - SOC can recommend; business/system owner accepts residual risk.
                  - High-risk paths (internet RDP to DC) should rarely clear exception review.
                  - RACI fails when Accountable is "TBD" or "the cloud."

                How to answer on the exam:
                1. Find who owns the decision.
                  2. Prefer documented exception answers.
                  3. Reject infinite silent risk.

                Common trap: SOC 'accepting' residual risk for the business with no owner. Near-miss: pretty RACI diagrams with no human names.

                Remember: Exceptions without owners are just future incidents with paperwork missing.
                """),
            ("RACI in practice", """
                Where you see this at work: who is Responsible vs Accountable for disabling legacy auth?

                In Security+ terms, that is using RACI vocabulary without drowning in corporate theater.

                Accountable owns the outcome. Responsible does the work. Consulted/informed as needed.

                Technical specifics:
                - Exam may not require perfect RACI charts; it requires clear ownership
                  - Name a human, not 'the cloud'
                  - SOC executes contain; owners accept residual after eradicate

                Worked example:
                IT ops may be Responsible for the Entra toggle. CISO or system owner is Accountable for residual identity risk. Write both names.

                How to answer on the exam:
                1. Look for named owners.
                  2. Separate doer vs accepter of risk.
                  3. Tie to exception dates.

                Common trap: matrix diagrams with no names.

                Remember: Clarity of ownership beats fancy charts.
                """),
        ],
        [
            _mc("Internet RDP with verbal vendor approval and no expiry. Missing?",
                ["Nothing", "Governance exception: owner, written approval, review date: plus better architecture",
                 "Only screensaver", "Deleting firewall logs"], 1,
                "Exceptions need owners.",
                "Correct. Documented, owned, reviewed. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Data owner role includes:",
                ["Ignoring classification", "Accountability for data handling decisions",
                 "Opening 3389", "Disabling MFA"], 1,
                "Ownership of data risk."),
            _mc("RACI helps because:",
                ["Fonts", "Clear who is Responsible/Accountable for control outcomes",
                 "It replaces backups", "It is a CVE"], 1,
                "Ambiguity kills."),
        ],
        [
            _qz("q_d5_02a", "Exception review date purpose:",
                ["Force re-evaluation so risk does not become permanent drift",
                 "Open RDP", "Disable SIEM", "Shame users"], 0,
                "Correct. Time-box. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_02b", "Security committee usefulness:",
                ["Cross-functional risk decisions with authority", "Only pizza",
                 "Only toner", "Only memes"], 0,
                "Correct. Governance forum. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_02c", "System owner vs SOC:",
                ["SOC owns patching always alone", "Owner accountable for system risk; SOC detects/responds",
                 "Neither documents anything", "Owner opens 3389 freely"], 1,
                "Correct. Split duties. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_02d", "Hallway exception is:",
                ["Strong governance", "Weak: not auditable or time-boxed",
                 "Required ZT", "A honeypot"], 1,
                "Correct. Write it down. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_03_risk_process", "d5_oversight", "5.2",
        "Risk management process", 18,
        ["Risk Assessment", "Likelihood", "Impact", "Risk Register"],
        [
            ("Risk process basics", """
                Risk is the combination of likelihood and impact for a threat exploiting a vulnerability against an asset. Risk management is identifying, analyzing, evaluating, treating, and monitoring that risk.

                Where you see this at work: open RDP to a DC is high impact. Commodity DROP noise on TCP 445 with no path is lower. You identify, analyze likelihood × impact, compare to appetite, then treat.

                In Security+ terms, that is risk identification and analysis ahead of treatment.

                Process beats:
                  1. Identify assets / threats / vulnerabilities
                  2. Analyze likelihood × impact (qualitative or quantitative)
                  3. Evaluate against appetite / tolerance
                  4. Treat (next lesson)
                  5. Monitor and review

                Technical specifics:
                - Inherent risk is before controls; residual risk remains after controls
                  - Qualitative ratings (high/medium/low) are fine on Security+ if reasoned
                  - Risk register tracks owner, rating, treatment, dates, residual
                  - Appetite is leadership's band; analysts escalate facts that exceed it
                  - SOC leftovers (open path, aged exception) should feed the register

                Worked example:
                NordVPN kill switch OFF with no owner:
                  - Identify: tunnel drop could expose traffic/path assumptions
                  - Analyze: impact depends on what was trusted to the VPN state
                  - Evaluate vs appetite → treat (turn ON) or formally accept with owner/date
                Do not skip analysis because a scanner is red elsewhere.

                                More desk clues:
                  - Inherent vs residual: before controls vs after controls.
                  - Qualitative ratings are fine on Security+ if likelihood and impact are reasoned.
                  - Risk register is where SOC leftovers become program work.
                  - Appetite is leadership's band; analysts escalate facts that exceed it.

                How to answer on the exam:
                1. Name asset + threat + weakness.
                  2. Rough likelihood/impact.
                  3. Do not skip to random tools before analysis.

                Common trap: treating all risks as equal or skipping analysis because a scanner is red. Near-miss: analyst silently 'accepting' DC RDP because the queue is busy.

                Remember: Risk process: identify → analyze → treat → monitor.
                """),
            ("Appetite and register", """
                Where you see this at work: leadership accepts some low risks; crown-jewel RDP exposure is outside appetite.

                In Security+ terms, that is risk appetite/tolerance and the risk register as governance tools.

                Register fields that matter: risk, owner, rating, treatment, dates, residual.

                Technical specifics:
                - SOC findings should feed the register when residual risk remains
                  - Appetite is leadership's call; analysts escalate facts
                  - Review dates keep accepted risks from becoming forgotten culture

                Worked example:
                Analysts escalate evidence. Owners accept residual risk inside appetite. Crown-jewel internet RDP should not hide as an undocumented shrug.

                How to answer on the exam:
                1. Separate analyst escalate vs owner accept.
                  2. Prefer named register entries.
                  3. Watch review dates.

                Common trap: analyst silently 'accepting' DC RDP because the queue is busy.

                Remember: Owners accept risk. Analysts surface it.
                """),
        ],
        [
            _mc("Kill switch OFF with no owner is:",
                ["Closed risk", "Untreated / poorly tracked risk",
                 "Encryption success", "Only CHG noise"], 1,
                "Register it.",
                "Correct. Silent hope is not management. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Likelihood × impact is used to:",
                ["Prioritize treatment", "Open RDP", "Disable MFA", "Delete logs"], 0,
                "Rank risks."),
            _mc("Risk register should include:",
                ["Owner, rating, treatment, review date", "Only jokes",
                 "Only attacker IPs forever with no owners", "Only toner"], 0,
                "Actionable tracking."),
        ],
        [
            _qz("q_d5_03a", "First step of risk process:",
                ["Buy random tools", "Identify what you care about (assets/processes)",
                 "Open 3389", "Disable SIEM"], 1,
                "Correct. Know the crown jewels. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_03b", "Qualitative risk ratings are:",
                ["Useless always", "Acceptable when consistent and action-driving",
                 "Only for OT", "Forbidden"], 1,
                "Correct. Pragmatism. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_03c", "Internet RDP to DC risk rating should be:",
                ["Low forever", "High/critical until removed",
                 "Informational only", "A honeypot success"], 1,
                "Correct. Path to identity store. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_03d", "Monitoring residual risk means:",
                ["Ignore after filing", "Watch indicators that the risk is changing",
                 "Delete the register", "Open more ports"], 1,
                "Correct. Living register. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_03e", "Inherent risk vs residual risk:",
                ["Inherent is after controls; residual is before",
                 "Inherent is before controls; residual remains after treatment",
                 "They are identical on every exam item",
                 "Residual means the risk was deleted forever"], 1,
                "Correct. Before vs after controls. Common trap: claiming residual is always "
                "zero after one mitigate. Remember: residual needs an owner and review date."),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_04_risk_treatment", "d5_oversight", "5.2",
        "Risk treatment options", 18,
        ["Mitigate", "Transfer", "Accept", "Avoid", "Risk Appetite"],
        [
            ("Treat the risk", """
                Risk treatment choices are mitigate (reduce), accept, transfer (insurance/contract), or avoid (stop the activity). Sometimes called risk response.

                Where you see this at work: mitigate by turning kill switch ON, disabling legacy auth, removing 3389. Accept a low lab risk with owner and date. Transfer some cyber residual via insurance. Avoid by not offering internet RDP to identity stores at all.

                In Security+ terms, that is risk treatment options and when each fits.

                Treatment map:
                  Mitigate / reduce → controls that lower likelihood or impact
                  Accept → informed, owned, documented
                  Transfer → share residual (insurance, contract). Not a magic delete
                  Avoid → stop doing the risky thing

                Technical specifics:
                - Mitigate examples: kill switch ON, disable legacy auth, remove 3389, ASR on
                  - Accept examples: low lab risk with owner/date; never silent DC exposure
                  - Transfer examples: insurance/contracts still need operational controls
                  - Avoid examples: do not offer internet RDP to DCs
                  - Compensating controls are mitigation when the preferred control is blocked
                  - Acceptance without owner/date is denial

                Worked example:
                Open internet RDP to DC: avoid/mitigate (remove path), not quiet accept. Insurance without MFA is not responsible transfer theater. After MFA and legacy auth off, some phishing residual remains; owner tracks it with a review date (mature residual acceptance).

                                More desk clues:
                  - Mitigate examples: turn kill switch ON, disable legacy auth, remove 3389.
                  - Accept examples: low lab risk with owner/date, never silent DC exposure.
                  - Transfer examples: insurance/contracts still need operational controls.
                  - Avoid examples: do not offer internet RDP to identity stores at all.

                How to answer on the exam:
                1. Match treatment to appetite and asset.
                  2. Demand owner/date for accept.
                  3. Prefer path removal for crown jewels.

                Common trap: calling undocumented exposure 'accepted risk.' Near-miss: 'we mitigated, so risk is zero forever.'

                Remember: Treatments need owners. Acceptance is a decision, not a shrug.
                """),
            ("Residual risk", """
                Where you see this at work: after MFA and legacy auth off, some phishing residual remains; owner tracks it.

                In Security+ terms, that is residual risk after controls.

                Always ask: what residual remains, who owns it, when reviewed?

                Technical specifics:
                - Residual can be low but never mythical zero for human systems
                  - Feed residual into awareness and detection tunes
                  - Register status should show residual rating after treatment

                Worked example:
                Mitigation lowered likelihood; residual accepted with review date is mature. Claiming zero risk after one control is not.

                How to answer on the exam:
                1. Name residual.
                  2. Name owner.
                  3. Schedule review.

                Common trap: 'we mitigated, so risk is zero forever.'

                Remember: Residual risk is normal. Unowned residual is not.
                """),
        ],
        [
            _mc("Leave kill switch OFF with no owner or date. Treatment?",
                ["Avoidance", "Undocumented acceptance: the worst kind",
                 "Transfer to ISP of ransomware", "Mitigate: OFF is a control"], 1,
                "Accept must be conscious.",
                "Correct. Mitigate would be turning it ON. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Removing internet RDP entirely is:",
                ["Avoid / mitigate the exposure path", "Transfer only",
                 "Accept forever", "Only Domain 4 SIEM"], 0,
                "Stop the activity/path."),
            _mc("Cyber insurance is primarily:",
                ["Transfer (with caveats): not a substitute for controls",
                 "Mitigation that patches DCs", "Physical cage", "A honeypot"], 0,
                "Money risk shift, not magic."),
        ],
        [
            _qz("q_d5_04a", "Mitigate means:",
                ["Ignore", "Reduce likelihood/impact with controls",
                 "Hope", "Delete register"], 1,
                "Correct. Treat actively. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_04b", "Valid acceptance includes:",
                ["Owner + rationale + review date", "Silence", "Open RDP secretly",
                 "Shame analysts"], 0,
                "Correct. Conscious accept. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_04c", "Risk appetite is:",
                ["How much risk leadership allows in pursuit of business",
                 "Only CVE count", "Only toner", "Only RDP"], 0,
                "Correct. Leadership band. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_04d", "Transfer without residual ops ownership is:",
                ["Complete safety", "Misunderstanding: you still operate controls",
                 "Required", "A backup"], 1,
                "Correct. MSP ≠ absolution. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_04e", "Documented accept of kill switch OFF needs at minimum:",
                ["Silence and hope", "Owner, rationale, and review date",
                 "Open RDP to the DC", "Deleting the risk register"], 1,
                "Correct. Acceptance is a decision with an owner and a review date. "
                "Common trap: calling undocumented exposure accepted risk. "
                "Remember: accept is owned, dated, and conscious."),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_05_third_party", "d5_oversight", "5.3",
        "Third-party risk", 18,
        ["Vendor Risk", "Due Diligence", "SOC 2", "Right to Audit", "Supply Chain"],
        [
            ("Vendors are in your blast radius", """
                Third-party risk covers vendors, MSPs, SaaS, and supply-chain partners who can hurt you through access, data, or updates.

                Where you see this at work: mail filter vendor questionnaire before buy, MSP standing admin review, SaaS holding customer data, and a compromised updater story. Offboard means keys, apps, groups, SSO, and shared mailboxes, not only a goodbye email.

                In Security+ terms, that is third-party risk assessment and ongoing management.

                Third-party beats:
                  1. Due diligence before buy (questionnaires, SOC reports, security review)
                  2. Contracts: security clauses, breach notice, data handling
                  3. Least privilege integration
                  4. Continuous monitoring / access reviews
                  5. Offboard vendors fully

                Technical specifics:
                - Tier vendors by data sensitivity and standing access depth
                  - Standing domain admin for MSP without review = supply-chain style risk
                  - Review MSP/VPN/admin accounts on a calendar, not only at purchase
                  - Shared responsibility does not vanish because SaaS is pretty
                  - Their breach notice clause matters when their incident becomes yours
                  - Right to audit / evidence requests vary by contract

                Worked example:
                Vendor questionnaire before buying a mail filter = managerial third-party review. MSP forever-admin without review = unmanaged third-party risk. Pilot SaaS with ten unused admin accounts last year = lifecycle failure; revoke.

                                More desk clues:
                  - Tier vendors by data sensitivity and standing access depth.
                  - Review MSP/VPN/admin accounts on a calendar, not only at purchase.
                  - Offboard integrations: keys, apps, groups, SSO, shared mailboxes.
                  - Their breach notice clause matters when their incident becomes yours.

                How to answer on the exam:
                1. Ask what data/access the third party has.
                  2. Prefer least privilege + review answers.
                  3. Include offboarding.

                Common trap: trusting logos instead of access reviews. Near-miss: one-time questionnaire forever.

                Remember: Third parties inherit your blast radius. Review them like it.
                """),
            ("Ongoing management", """
                Where you see this at work: SaaS app still has ten unused admin accounts from a pilot last year.

                In Security+ terms, that is continuous third-party access hygiene.

                Ongoing: inventory integrations, review admins, monitor alerts, renew diligence on tier-1 vendors.

                Technical specifics:
                - Tier vendors by data sensitivity / access depth
                  - Incident clauses matter when their breach becomes your incident
                  - Offboard: keys, apps, groups, SSO, shared mailboxes

                Worked example:
                Pilot leftovers are third-party lifecycle failures. Revoke, then review how they stayed for a year.

                How to answer on the exam:
                1. Tier the vendor.
                  2. Review access.
                  3. Keep contract obligations in view.

                Common trap: one-time questionnaire forever.

                Remember: Third-party risk is a loop, not a purchase checkbox.
                """),
        ],
        [
            _mc("BEC via mail path you pay for; vendor has no independent report. Next?",
                ["Ignore vendor; only retrain CFO",
                 "Start third-party review: data touched, controls, contract notify, alternatives",
                 "Give vendor domain admin", "Accept forever with no register line"], 1,
                "5.3 lifecycle.",
                "Correct. Due diligence after failure. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("SOC 2 report is:",
                ["Proof of zero risk", "Independent-ish assurance input: still read scope/exceptions",
                 "A firewall rule", "RTO"], 1,
                "Useful, not magic."),
            _mc("Right-to-audit clause helps you:",
                ["Never assess", "Contractually inspect when risk warrants",
                 "Open RDP", "Disable MFA"], 1,
                "Teeth in the contract."),
        ],
        [
            _qz("q_d5_05a", "Third-party inventory should list:",
                ["Who has data/access and how critical", "Only lunch menus",
                 "Only attacker IPs", "Only toner brands"], 0,
                "Correct. Know your vendors. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_05b", "Continuous monitoring of vendors means:",
                ["One questionnaire forever", "Ongoing review as access/data changes",
                 "Never renew contracts", "Open their RDP"], 1,
                "Correct. Living process. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_05c", "MSP standing domain admin is:",
                ["Low third-party risk", "High: privileged supply-chain style access",
                 "Only Domain 1", "A honeypot success"], 1,
                "Correct. Privilege to vendors. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_05d", "Contract breach notification clauses matter for:",
                ["Learning about their incidents that affect you", "Opening 3389",
                 "Disabling SIEM", "Skipping MFA"], 0,
                "Correct. Timely awareness. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_06_compliance", "d5_oversight", "5.4",
        "Compliance essentials without the novel", 17,
        ["Compliance", "Regulation", "Privacy", "Retention"],
        [
            ("Compliance vs security", """
                Compliance means meeting required rules (laws, regulations, contracts, internal policies). Security is the actual protection. You want both. Compliance alone can be checkbox theater.

                Where you see this at work: a PCI or privacy obligation forces encryption and access logging. Passing an audit last year does not mean open RDP is fine today. Retention rules often help investigations and audits together.

                In Security+ terms, that is compliance requirements as drivers, not substitutes, for security controls.

                Compliance beats:
                  1. Know applicable obligations at a high level
                  2. Map controls to requirements with owners
                  3. Evidence continuously, not only at audit week
                  4. Fix say/do gaps

                Technical specifics:
                - Map each requirement to a control owner and evidence location
                  - Logging/retention may be compliance-driven and investigation-helpful
                  - Privacy rules shape how investigation packs are shared
                  - Contractual customer requirements can bind Boundry client work
                  - Encrypted backups may satisfy a letter and still fail ransomware if online-only

                Worked example:
                Passing last year's audit does not bless this week's open RDP. Meet the letter and the risk: encrypt backups and keep an offline/immutable copy. Evidence habit: export MFA/CA configs monthly so audit week is not a scramble.

                                More desk clues:
                  - Map each requirement to a control owner and evidence location.
                  - Retention/logging rules often help investigations and audits together.
                  - Passing last year's audit does not bless this week's open RDP.
                  - Privacy rules shape how investigation packs are shared.

                How to answer on the exam:
                1. Separate 'required by rule' from 'enough to be safe.'
                  2. Prefer continuous evidence.
                  3. Fix real exposure even if last audit passed.

                Common trap: checkbox compliance while crown-jewel paths stay open. Near-miss: evidence that exists only in one person's head.

                Remember: Compliance is necessary. It is not automatic security.
                """),
            ("Evidence habit", """
                Where you see this at work: audit asks for MFA proof; you scramble screenshots from one laptop.

                In Security+ terms, that is continuous control evidence.

                Evidence habit: export configs, ticket trails, access reviews, training completion on a cadence.

                Technical specifics:
                - SIEM/ticket history helps prove detective/response controls
                  - Change tickets prove governance of exceptions
                  - Store evidence where the next admin can find it

                Worked example:
                Teams that evidence monthly do not panic yearly. Scramble culture is a finding.

                How to answer on the exam:
                1. Prefer ongoing evidence answers.
                  2. Tie controls to owners.
                  3. Keep exports retrievable.

                Common trap: evidence that exists only in one person's head.

                Remember: If you cannot show it, auditors assume it does not exist.
                """),
        ],
        [
            _mc("Compliance vs security:",
                ["Identical always", "Overlapping; compliance is required mapping, security is risk outcomes",
                 "Compliance replaces IR", "Security forbids tickets"], 1,
                "Related, not synonyms."),
            _mc("Log retention should be:",
                ["Zero days always", "Defined by investigation needs + legal/contractual rules",
                 "Infinite cleartext forever with no purpose", "Only toner logs"], 1,
                "Policy-backed retention."),
            _mc("Privacy compliance often requires:",
                ["Open RDP", "Lawful handling, minimization, breach processes",
                 "Disable MFA", "Delete all SIEM"], 1,
                "Data subject duties."),
        ],
        [
            _qz("q_d5_06a", "Compliance evidence examples:",
                ["Policies, logs, access reviews, training records", "Only memes",
                 "Only open ports", "Only attacker blogs"], 0,
                "Correct. Show your work. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_06b", "Keeping every email forever without purpose risks:",
                ["Privacy / retention violations and breach blast radius", "Better RTO magic",
                 "Stronger MFA", "Faster patching"], 0,
                "Correct. Minimize. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_06c", "Contractual security requirements are:",
                ["Optional vibes", "Binding compliance inputs for that customer",
                 "Only Domain 2 IOCs", "Physical only"], 1,
                "Correct. MSA/SOW duties. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_06d", "Breach notification timelines come from:",
                ["Analyst mood", "Law/contract: know the clock",
                 "Only toner vendors", "Only RDP"], 1,
                "Correct. Clock starts. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_07_audits_assessments", "d5_oversight", "5.5",
        "Audits and assessments", 17,
        ["Internal Audit", "External Audit", "Assessment", "Evidence"],
        [
            ("Audits and assessments", """
                An audit checks against criteria and produces findings. An assessment evaluates posture more broadly. Internal vs external changes independence.

                Where you see this at work: internal audit samples firewall exceptions. External assessor reviews identity controls. Findings get owners, due dates, fix evidence, and retest. Vendor SOC reports inform diligence; they do not replace your access reviews.

                In Security+ terms, that is audits vs assessments and finding remediation.

                Map:
                  Internal audit → independence inside org varies by design
                  External audit/assessment → outside party
                  Finding → gap vs criteria
                  Remediation → fix + evidence + retest / owner sign-off

                Technical specifics:
                - Finding closure needs fix + evidence + owner sign-off, not a promise
                  - Check scope exclusions that hide crown jewels
                  - Self-assessment helps; independent audit claims need real independence
                  - Vendor SOC reports inform diligence; they do not replace access reviews
                  - Penetration tests and vuln scans are assessment types (next lesson contrast)

                Worked example:
                Finding: legacy auth enabled against policy. Remediation: disable + evidence SigninLogs/CA export + owner sign-off. If DC RDP was scoped out every year, the clean report is marketing.

                                More desk clues:
                  - Finding closure needs fix + evidence + owner sign-off, not a promise.
                  - Check scope exclusions that hide crown jewels.
                  - Self-assessment helps; independent audit claims need real independence.
                  - Vendor SOC reports inform diligence; they do not replace access reviews.

                How to answer on the exam:
                1. Identify audit vs assessment intent.
                  2. Prefer owned remediation.
                  3. Ask for evidence of closure.

                Common trap: shelving findings until the next audit cycle without risk treatment. Near-miss: trusting a clean report with suspicious scope exclusions.

                Remember: Findings need owners and due dates, not binders.
                """),
            ("Independence and scope", """
                Where you see this at work: the team that built the firewall also 'audits' itself with no outside review.

                In Security+ terms, that is independence and scope clarity.

                Good practice: clear scope, criteria, independence appropriate to the claim.

                Technical specifics:
                - Self-assessment is useful but not the same as independent audit
                  - Scope games hide crown jewels
                  - Ask what was out of scope before celebrating a clean report

                Worked example:
                If DC RDP was scoped out every year, the clean report is marketing. Widen scope or treat the exclusion as residual risk with an owner.

                How to answer on the exam:
                1. Check scope.
                  2. Check independence claims.
                  3. Follow findings to closure.

                Common trap: trusting a clean report with suspicious scope exclusions.

                Remember: Scope and independence decide how much a report means.
                """),
        ],
        [
            _mc("Omit repeat BECs from reports so the register stays green. That is:",
                ["Good governance", "Unacceptable: hide findings destroys trust and risk decisions",
                 "Required compliance", "A honeypot"], 1,
                "Honesty."),
            _mc("External audit primarily provides:",
                ["Free malware", "Independent examination against criteria",
                 "Open RDP", "Disabled MFA"], 1,
                "Outside view."),
            _mc("Best audit evidence for MFA enforcement?",
                ["Verbal claim", "Policy + Entra CA screenshot/export + sample SigninLogs",
                 "Only a poster", "Only hope"], 1,
                "Show config + operation."),
        ],
        [
            _qz("q_d5_07a", "Gap assessment purpose:",
                ["Compare current vs required controls", "Open 3389",
                 "Disable SIEM", "Shame users"], 0,
                "Correct. Find missing controls. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_07b", "Internal audit should be:",
                ["The same team grading its own homework without independence",
                 "Organized for objectivity as much as practical",
                 "Deleted", "Only memes"], 1,
                "Correct. Independence matters. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_07c", "Customer security questionnaire is a form of:",
                ["Assessment / assurance request", "EDR isolate", "RTO", "Base64"], 0,
                "Correct. Third-party asks you. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_07d", "Finding without owner in audit report:",
                ["Closed", "Likely to rot: demand owners and dates",
                 "Automatic mitigate", "Physical only"], 1,
                "Correct. Ownership. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_08_pen_vs_vuln", "d5_oversight", "5.5",
        "Penetration test vs vulnerability scan", 18,
        ["Penetration Test", "Vulnerability Scan", "Red Team", "Bug Bounty"],
        [
            ("Pen test vs vuln scan", """
                A vulnerability scan finds known weaknesses broadly and often. A penetration test simulates attacker techniques to prove exploitable paths, usually with defined scope and rules of engagement (ROE).

                Where you see this at work: weekly Nessus finds missing patches and open ports. An annual pen test proves whether an open path can reach the domain controller. Different questions, different outputs, same need for remediation owners.

                In Security+ terms, that is penetration testing versus vulnerability scanning.

                Contrast:
                  Vuln scan → breadth, known issues, frequent, lower impact if configured safely
                  Pen test → depth, exploitation/proof, scoped, higher skill/cost
                  Red team → broader adversary simulation (related idea)
                  Bug bounty → external researcher program (related idea)

                Technical specifics:
                - Scans need authorization and safety (Domain 4 overlap): CHG, scope, stop conditions
                  - Pen tests need ROE, contacts, data handling, get-out-of-jail letter, stop conditions
                  - Scan cadence can be weekly/monthly; pen tests are usually deeper and less frequent
                  - Neither replaces patching or path removal
                  - Both produce findings that enter the same remediation/risk process
                  - A clean scan does not prove no exploitable business path exists

                Worked example:
                Open RDP may show on a scan as exposure/misconfig and also be a pen-test finding if exploited to the DC.
                  - Question wants breadth discovery → vuln scan
                  - Question wants exploit proof / path to crown jewel → pen test
                  - Skipping fixes because 'pen test next year' fails both programs

                                More desk clues:
                  - Scan cadence can be weekly/monthly. Pen tests are usually deeper and less frequent.
                  - ROE and authorization letters are mandatory before offensive testing.
                  - Both produce findings that enter the same remediation/risk process.
                  - A clean scan does not prove no exploitable business path exists.

                How to answer on the exam:
                1. Ask if the question wants breadth discovery or exploit proof.
                  2. Match scan vs pen test.
                  3. Keep authorization in view.

                Common trap: calling a vuln scan a pen test because it has a red logo, or skipping fixes because a pen test is scheduled next year. Near-miss: equating any scanner output with 'we were pen tested.'

                Remember: Scan finds. Pen test proves. Both need remediation owners.
                """),
            ("Rules of engagement", """
                Where you see this at work: tester starts attacking prod payroll at noon with no window or contact.

                In Security+ terms, that is authorization and ROE for offensive assessments.

                ROE beats: scope, timing, contacts, data handling, stop conditions, get-out-of-jail letter.

                Technical specifics:
                - Unauthorized testing is illegal and an incident
                  - Findings still need treatment like other risks (owner, due date, verify)
                  - Production windows and emergency contacts prevent payroll outages

                Worked example:
                No ROE = stop. Good programs treat findings through the risk register, not a slide deck that dies in email.

                How to answer on the exam:
                1. Demand authorization/scope.
                  2. Separate scan vs exploit depth.
                  3. Route findings to owners.

                Common trap: equating any scanner output with 'we were pen tested.'

                Remember: No authorization, no test. Findings still need owners.
                """),
        ],
        [
            _mc("Penetration test vs vuln scan: pen test is:",
                ["Only more CVEs automatically", "Scoped exploit/chain attempt with narrative proof",
                 "Always unauthorized", "Only Domain 1"], 1,
                "Depth and proof."),
            _mc("Bug bounty is roughly:",
                ["Paying researchers for valid vulnerability reports under rules",
                 "Opening RDP to the world without rules", "Disabling MFA", "A cold site"], 0,
                "Structured disclosure."),
            _mc("Best use of pen test report?",
                ["Wallpaper", "Prioritized remediation with owners",
                 "Ignore CRITICAL", "Shame SOC only"], 1,
                "Action."),
        ],
        [
            _qz("q_d5_08a", "Vuln scan strength:",
                ["Breadth and repeatability", "Always proves ransomware",
                 "Replaces IR", "Opens 3389"], 0,
                "Correct. Coverage. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_08b", "Red team differs by often adding:",
                ["Stealth/objectives beyond simple CVE checklist", "Only toner findings",
                 "Only AUP typos", "Only RPO"], 0,
                "Correct. Adversary emulation. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_08c", "Unauthorized scanning of prod is:",
                ["Fine pen test", "Possibly illegal/incident: need authorization",
                 "Required nightly", "A honeypot"], 1,
                "Correct. Rules of engagement. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_08d", "After pen test finds legacy auth path:",
                ["File risk + remediate (disable) with owner", "Hide the finding",
                 "Open more RDP", "Disable logging"], 0,
                "Correct. Treat. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_08e", "Rules of engagement (ROE) for a pen test should include:",
                ["Only the scanner logo color",
                 "Scope, timing, contacts, data handling, and stop conditions",
                 "Permission to attack any system anytime",
                 "A promise that findings need no owners"], 1,
                "Correct. Authorization and safety first. Common trap: equating any scanner "
                "output with a pen test. Remember: no ROE, no test."),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_09_awareness_basics", "d5_oversight", "5.6",
        "Security awareness basics", 17,
        ["Security Awareness", "Phishing Simulation", "Reporting Culture"],
        [
            ("Awareness that changes behavior", """
                Security awareness teaches people how to recognize and report risks. It is a control layer, not a substitute for technical guardrails like ASR, MFA, and DLP.

                Where you see this at work: phishing simulations, short role tips for finance callbacks, and reporting paths that do not shame accidental clicks. Metrics track report rate and time-to-report, not only course completion checkmarks.

                In Security+ terms, that is security awareness program basics.

                Awareness beats:
                  1. Relevant content (phishing, BEC, USB, travel)
                  2. Frequency that sticks
                  3. Easy reporting
                  4. Metrics (report rate, click trends) without shame culture
                  5. Pair with technical ASR / MFA / DLP

                Technical specifics:
                - Measure report quality and time-to-report, not only completion checkmarks
                  - Pair every awareness theme with a technical control (ASR, MFA, DLP)
                  - Keep reporting frictionless: button/mailbox and a thank-you response
                  - Shame culture suppresses the human sensor network
                  - Poster-only after confirmed BEC is incomplete
                  - Stale training (14+ months) is a process gap

                Worked example:
                After Invoice.xlsm: AUP helps set expectations, but ASR still required. Awareness last updated 14 months ago is a process gap. Annual boring slideshow as the only control for active phishing fails.

                                More desk clues:
                  - Measure report quality and time-to-report, not only completion checkmarks.
                  - Pair every awareness theme with a technical control (ASR, MFA, DLP).
                  - Keep reporting frictionless: button/mailbox and a thank-you response.
                  - Shame culture suppresses the human sensor network.

                How to answer on the exam:
                1. Prefer awareness + technical pairing.
                  2. Reject shame-only answers.
                  3. Look for reporting path clarity.

                Common trap: annual boring slideshow as the only control for active phishing. Near-miss: mocking the clicker in all-hands so nobody reports next time.

                Remember: Awareness steers humans. Technical controls still close paths.
                """),
            ("Reporting culture", """
                Where you see this at work: user almost clicks, then reports. Analyst thanks them and checks the campaign.

                In Security+ terms, that is positive reporting culture as part of awareness effectiveness.

                Good culture: fast thank-you, no public shaming, rapid block of related IOCs.

                Technical specifics:
                - Report button / dedicated mailbox
                  - Feed reports into detections and block lists
                  - Track time from report to block

                Worked example:
                Punishing reporters kills the detection source you need. Thank, hunt, harden.

                How to answer on the exam:
                1. Reward reporting.
                  2. Fix paths.
                  3. Keep training fresh.

                Common trap: mocking the clicker in all-hands.

                Remember: People report more when it is safe to report.
                """),
        ],
        [
            _mc("Repeat Invoice.xlsm clicks in HR. Best awareness-shaped response?",
                ["HR-specific phishing/macro briefing AND technical block (ASR / mail policy)",
                 "Single joke poster and no technical change", "Shame in all-hands",
                 "Turn off EDR"], 0,
                "Role-based + technical.",
                "Correct. Training-only is the near-miss. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Public shaming clickers tends to:",
                ["Improve reporting", "Reduce reporting and hide future incidents",
                 "Patch DCs", "Set RTO"], 1,
                "Culture."),
            _mc("Phishing simulation purpose?",
                ["Punish only", "Measure/teach reporting and click resistance",
                 "Open RDP", "Replace backups"], 1,
                "Learn safely."),
        ],
        [
            _qz("q_d5_09a", "Awareness without technical controls is:",
                ["Usually incomplete", "Always enough", "Forbidden", "Only for OT"], 0,
                "Correct. Defense in depth. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_09b", "Reporting culture means:",
                ["Easy, non-punitive reporting of phish/incidents", "Only silent suffering",
                 "Only attacker tips", "Only toner tickets"], 0,
                "Correct. Psychological safety. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_09c", "Generic annual CBT only:",
                ["May miss role-specific risks like finance BEC", "Fixes open RDP",
                 "Disables legacy auth", "Sets immutable backups"], 0,
                "Correct. Target the audience. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_09d", "After sim fail, best next step:",
                ["Coach + ensure technical guardrails exist", "Fire immediately always",
                 "Open 3389", "Delete mail logs"], 0,
                "Correct. Improve. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_10_awareness_role", "d5_oversight", "5.6",
        "Role-based awareness and executives", 17,
        ["Role-Based Training", "Executive Awareness", "Insider Risk", "Social Engineering"],
        [
            ("Role-based awareness", """
                Different jobs need different awareness. Finance is not HR is not admins. Privileged users are higher-value targets.

                Where you see this at work: finance gets BEC callback drills and payment-change verification. Admins get phishing-resistant MFA and privileged account hygiene. Helpdesk gets identity verification before resets. Developers get secrets-in-git training.

                In Security+ terms, that is role-based security awareness and privileged-user training.

                Role map:
                  Finance → BEC / payment change verification
                  Executives → high-value targeting, travel process
                  Admins → privileged phishing, tool hygiene, no daily email on DA
                  Helpdesk → verify before reset; MFA fatigue resistance
                  All staff → phishing basics + reporting

                Technical specifics:
                - Track metrics by role so exec/finance risk is not hidden in org averages
                  - Privileged users are higher-value targets; pair training with IAM controls
                  - Number matching / phishing-resistant MFA reduces fatigue abuse
                  - Helpdesk verification procedures are awareness + procedure
                  - Generic annual training alone fails finance BEC scenarios
                  - Finance drills: out-of-band callback before payment-detail changes
                  - Admins: no daily email on Domain Admin / Global Admin accounts

                Worked example:
                Generic annual training alone fails finance BEC. Add callback drills + technical forward controls. Helpdesk resetting a VIP without verification is an awareness and process miss. Measure finance report rate separately so org-wide averages do not hide the risk.

                                More desk clues:
                  - Finance: callback drills and payment-change verification.
                  - Helpdesk: identity verification before resets; MFA fatigue resistance.
                  - Admins: no daily email on privileged accounts; tool hygiene.
                  - Track metrics by role so exec/finance risk is not hidden in org averages.

                How to answer on the exam:
                1. Match training to role risk.
                  2. Pair with technical controls.
                  3. Keep privileged training stricter.

                Common trap: one identical slideshow for every role forever. Near-miss: assuming admins already know and skipping their training.

                Remember: Train the job people actually do.
                """),
            ("Privileged targets", """
                Where you see this at work: helpdesk and domain admins receive convincing MFA fatigue or helpdesk impersonation lures.

                In Security+ terms, that is elevated awareness for privileged and helpdesk roles.

                Extra topics: MFA fatigue, vishing, password reset verification, out-of-band checks.

                Technical specifics:
                - Number matching / phishing-resistant MFA reduces fatigue abuse
                  - Helpdesk verification procedures are awareness + procedure
                  - No daily email on privileged admin accounts

                Worked example:
                Helpdesk resetting a VIP without verification is an awareness and process miss. Combine training with IAM tech and callbacks.

                How to answer on the exam:
                1. Identify privileged audience.
                  2. Prefer stricter process answers.
                  3. Combine with IAM tech.

                Common trap: assuming admins already know and skipping their training.

                Remember: Privileged users need privileged training.
                """),
        ],
        [
            _mc("Finance-specific awareness should emphasize:",
                ["Only generic password length", "Callback on payment changes / BEC patterns",
                 "Opening RDP", "Disabling MFA"], 1,
                "Match the fraud."),
            _mc("Disabling MFA for executives for 'travel ease' is:",
                ["Good awareness", "Program failure: high-value users need stronger controls",
                 "Required compliance", "A honeypot"], 1,
                "Privilege needs more control."),
            _mc("Helpdesk social engineering training matters for IT because:",
                ["Attackers reset MFA/credentials via support channels", "Only toner",
                 "Only RPO", "Only cold sites"], 0,
                "Process abuse."),
        ],
        [
            _qz("q_d5_10a", "Role-based training purpose:",
                ["Relevant threats per job function", "One meme for all forever",
                 "Open 3389", "Skip technical controls"], 0,
                "Correct. Relevance. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_10b", "Insider risk signals might include:",
                ["Unusual data staging / access outside role", "Only successful CHG",
                 "Only TLS versions", "Only VLAN names"], 0,
                "Correct. Behaviour + data. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_10c", "Executive OSINT awareness covers:",
                ["Public info used in spearphish", "Only printer drivers",
                 "Only RTO math", "Only NIDS signatures"], 0,
                "Correct. Targeting. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_10d", "Best program combo after finance BEC:",
                ["Finance BEC training + legacy auth off + DLP forwards + callback process",
                 "Poster only", "Shame CFO only", "Open OWA on 3389"], 0,
                "Correct. People + tech + process. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )

    add(
        "sp_d5_11_oversight_tieback", "d5_oversight", "5.1",
        "Close the loop after IR", 18,
        ["Lessons Learned", "Risk Register", "Metrics", "Continuous Improvement"],
        [
            ("Tie oversight back to the ticket", """
                Domain 5 closes the loop: governance, risk, vendors, compliance, audits, and awareness exist so tomorrow's ticket is less likely. Oversight without ops feedback is theater.

                Where you see this at work: after BEC you disable legacy auth (ops), update the standard (governance), record residual risk (risk), brief finance (awareness), review vendor mail filter access if implicated, and evidence the change for audit.

                In Security+ terms, that is tying program oversight actions back to operational incidents.

                Tieback loop:
                  1. Incident / finding happens
                  2. Contain in ops (Domain 4)
                  3. Update control / policy / exception (Domain 5)
                  4. Assign residual risk owner
                  5. Train the affected role
                  6. Evidence for audit

                Technical specifics:
                - After IR, name the program object that changes: standard, exception, risk row, training, vendor access
                  - Metrics that matter: repeat incident rate, aged exceptions, privileged training completion by role
                  - Unowned 'next steps' in tickets become next quarter's identical alert
                  - Portfolio What/Why/Disposition/Next is an oversight-friendly artifact
                  - Vendors implicated in the path get access reviews

                Worked example:
                Repeat Invoice.xlsm without ASR update + role training means oversight failed to close the loop even if each ticket was resolved. Interview answer: disable legacy auth, forward controls, finance callback drill, who owns residual phishing risk, and where evidence lives.

                                More desk clues:
                  - After IR, name the program object that changes: standard, exception, risk row, training, vendor access.
                  - Metrics that matter: repeat incident rate, aged exceptions, privileged training completion.
                  - Unowned "next steps" in tickets become next quarter's identical alert.
                  - Oversight talk-track beats "we told users to be careful."

                How to answer on the exam:
                1. After the firefight, ask what program object changes.
                  2. Name owner and date.
                  3. Prefer loop-closing answers over one-off heroics.

                Common trap: closing incidents forever with no policy/risk/awareness follow-through. Near-miss: only saying we told users to be careful.

                Remember: Owner, treatment, vendor, awareness. Close the loop.
                """),
            ("Program talk-track", """
                Where you see this at work: interview: how do you prevent the same BEC next quarter?

                In Security+ terms, that is program-level prevention language after IR.

                Talk-track: technical eradicate + standard update + finance drill + residual risk review + evidence.

                Technical specifics:
                - Metrics: repeat incident rate, exception aging, training completion by role
                  - Escalation path into leadership when appetite is exceeded
                  - Oversight talk-track beats 'we told users to be careful'

                Worked example:
                Strong answer names disable legacy auth, forward controls, finance callback, and who owns residual phishing risk. Weak answer stops at awareness posters.

                How to answer on the exam:
                1. Move from ticket language to program language.
                  2. Keep owners visible.
                  3. Mention evidence/metrics lightly.

                Common trap: only saying we told users to be careful.

                Remember: Oversight is how one ticket becomes fewer tickets.
                """),
        ],
        [
            _mc("After IR, Domain 5 next step package?",
                ["Poster only and accept forever",
                 "Owner+expiry for residual risk, vendor review, role training, technical fix",
                 "Fire the analyst and declare victory", "Omit repeats from reports"], 1,
                "Program closure.",
                "Correct. Owner + vendor + awareness + tech. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Exception aging metric tracks:",
                ["How long accepted risks sit without review", "CPU temp only",
                 "Only toner", "Only RDP latency"], 0,
                "Governance health."),
            _mc("Continuous improvement means:",
                ["Incidents change controls, training, and register items", "Freeze forever",
                 "Hide findings", "Open more ports"], 0,
                "Learn."),
        ],
        [
            _qz("q_d5_11a", "Lessons learned without owners:",
                ["Theatre", "Actionable program change", "Automatic patch", "Open RDP"], 0,
                "Correct. Owners required. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_11b", "MTTR improvement suggests:",
                ["Faster containment/recovery craft", "More open 3389",
                 "Disabled logging", "No tickets"], 0,
                "Correct. Ops speed. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_11c", "Hiding repeat incidents from leadership:",
                ["Protects the business", "Blocks correct risk treatment: unacceptable",
                 "Required by Sec+", "A backup strategy"], 1,
                "Correct. Integrity of oversight. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d5_11d", "Best Career Lab proof of Domain 5 skill:",
                ["Portfolio case with residual risk + next owners", "Only memorizing port numbers",
                 "Only opening RDP", "Only disabling MFA"], 0,
                "Correct. Narrative + ownership. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d5",
    )
