"""D3 lesson specs for Phase 1 generator.

Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).
Depth: Option 1 ~15–20 min Show-me; work-facing picture + technical specifics.
"""
from __future__ import annotations


def d3_specs(add, _mc, _qz):
    """Register Domain 3 micro-lessons (9)."""

    add(
        "sp_d3_01_arch_models", "d3_architecture", "3.1",
        "Architecture models: on-prem, cloud, hybrid", 17,
        ["On-Premises", "IaaS", "PaaS", "SaaS", "Hybrid", "Shared Responsibility"],
        [
            ("Where the control lives", """
                Architecture models describe where systems run: on-premises, cloud, or hybrid. Shared responsibility means the provider and customer each own parts of security. You still own identity, data, and configuration even when the provider owns hardware.

                Where you see this at work: Boundry runs Entra ID (cloud identity), an on-prem domain controller, and SaaS mail. A cloud marketing slide does not make legacy auth safe.

                In Security+ terms, that is on-prem, IaaS, PaaS, SaaS, hybrid, and shared responsibility..

                Model map:
                  On-prem: you own more of the stack (DC, firewall, backups)
                  IaaS: provider hosts hardware; you harden VMs/NSGs/OS
                  PaaS: less OS duty; still identity, data, app config
                  SaaS: vendor runs the app; you still own identity, DLP, admin roles
                  Hybrid: mix; hunt the plane where the session lived

                Technical specifics:
                - SaaS mail BEC still needs identity + forwarding/DLP controls
                  - IaaS open NSG 3389 is primarily the customer's problem
                  - Hybrid: SigninLogs and on-prem 462x as needed
                  - OT/ICS and fragile legacy: segment + compensate, not internet RDP

                Worked example:
                SaaS mail still requires you to own identity, forwarding/DLP, admin roles. IaaS VM with open NSG 3389 is yours: customer network/OS config. Hybrid Entra + on-prem DC means hunt both cloud and on-prem sources.

                How to answer on the exam:
                1. Name the model in the question.
                  2. Ask which slice the customer still owns.
                  3. Pick logs/controls for that slice.

                Common trap: 'shared responsibility means the customer owns nothing' or 'cloud provider patches Hyper-V so legacy auth is fine.'

                Remember: Architecture model drives which logs you open and which controls you still owe.
                """),
            ("ICS / leftover systems", """
                Where you see this at work: a vendor wants internet RDP to a fragile OT panel 'because the plant software is old.'

                In Security+ terms, that is compensating controls and segmentation for systems you cannot patch like a laptop..

                Fragile system beats:
                  1. Segment away from the open internet
                  2. Prefer brokered access (jump/VPN/PAM)
                  3. Document compensating controls with owner and review

                Technical specifics:
                - On-prem DC exposure is critical: identity store + lateral potential
                  - Talk-track: pick sources by where the identity/session lived

                Worked example:
                OT/ICS gets compensating controls and segmentation, not internet RDP because the vendor said so.

                How to answer on the exam:
                1. Identify fragile/legacy constraints.
                  2. Prefer path removal + segment.
                  3. Reject 'cloud/SaaS means zero customer duty.'

                Common trap: treating on-prem crown jewels as if they were low-value SaaS toys.

                Remember: Provider ownership never deletes your identity duty.
                """),
        ],
        [
            _mc("SaaS mail still requires you to own:",
                ["Hypervisor patching only", "Identity, forwarding/DLP, admin roles",
                 "Nothing: shared responsibility is zero", "Only cage keys"], 1,
                "Customer side of SaaS.",
                "Correct. BEC proves SaaS customers still own identity and data controls."
                "Common trap: shared responsibility = zero customer duty."),
            _mc("IaaS VM with open NSG 3389 is whose problem primarily?",
                ["Only the cloud provider", "Yours: customer network/OS config",
                 "Only the ISP", "Nobody"], 1,
                "Shared responsibility.",
                "Correct. Provider does not configure your allow rules. Cloud is not a free pass. "),
            _mc("Hybrid Entra + on-prem DC means:",
                ["Ignore on-prem logs", "Hunt both cloud SigninLogs and on-prem 462x as needed",
                 "Disable MFA", "Trust VPN only"], 1,
                "Two planes.",
                "Correct. Architecture model drives which data sources you open. "),
        ],
        [
            _qz("q_d3_01a", "Shared responsibility means:",
                ["Provider owns all risk", "Split of duties; customer still owns identity/data/config",
                 "No patches ever", "Open RDP is required"], 1,
                "Correct. Know your slice. Provider ownership never deletes your identity duty. "),
            _qz("q_d3_01b", "PaaS reduces duty mainly on:",
                ["Identity forever", "OS patching compared to IaaS", "All DLP", "All IR"], 1,
                "Correct. Less OS, not zero security. Identity and data remain yours. "),
            _qz("q_d3_01c", "On-prem DC exposure is critical because:",
                ["It is SaaS", "Identity store + lateral potential", "It is only physical", "RPO"], 1,
                "Correct. Crown jewel. Identity store exposure is emergency-class. "),
            _qz("q_d3_01d", "Best hybrid talk-track:",
                ["Cloud means no tickets", "I pick sources by where the identity/session lived",
                 "Only use pfirewall", "Disable accounting"], 1,
                "Correct. Model → evidence. Follow where the session lived. "),
        ],
    )

    pbq_zt = {
        "id": "pbq_d3_zt",
        "kind": "map",
        "title": "Map the architecture control",
        "prompt": "For each Boundry failure, pick the architecture move that stops the class of incident.",
        "categories": [
            {"id": "remote", "label": "Remove exposure / VPN + PAM jump"},
            {"id": "zt", "label": "Zero Trust / Conditional Access + travel process"},
            {"id": "idarch", "label": "Disable legacy auth + inbox-rule / session policy"},
            {"id": "asr", "label": "Mail gateway + EDR ASR (Office → script)"},
        ],
        "items": [
            {"id": "rdp", "text": "ALLOW 3389 from 203.0.113.88 → PROD-DC01, no VPN", "answer": "remote"},
            {"id": "travel", "text": "ceo@ sign-in from Frankfurt; need a consistent grant/deny story", "answer": "zt"},
            {"id": "bec", "text": "Inbox rule created without MFA because legacy auth was on", "answer": "idarch"},
            {"id": "ps", "text": "Invoice.xlsm → excel.exe → powershell -enc on an HR PC", "answer": "asr"},
        ],
        "explain": (
            "Correct. RDP is a path problem. Travel is policy-per-session. BEC was identity protocol"
            "debt. Macros need mail+endpoint architecture. Match the control class to the failure class. Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d3_02_zero_trust_arch", "d3_architecture", "3.1",
        "Zero Trust and microsegmentation", 18,
        ["Zero Trust", "Microsegmentation", "Conditional Access", "Least Privilege"],
        [
            ("Ops definition that passes the exam", """
                Zero Trust rejects implicit trust from network location alone. You authenticate and authorize every session, assume breach, use least privilege, and validate continuously. Microsegmentation means splitting networks into small trust zones so malware cannot freely roam.

                Where you see this at work: CEO travel login is allowed because MFA passed and HR confirmed travel, not because 'they are on VPN.' HR PCs should not talk to DC admin ports by default.

                In Security+ terms, that is Zero Trust and microsegmentation as architecture, not a product sticker.

                ZT pillars in practice:
                  1. Verify explicitly (AuthN + AuthZ per session)
                  2. Least privilege
                  3. Assume breach / limit blast radius
                  4. Microsegmentation: separate trust tiers and admin paths
                  5. Conditional Access wraps policy around identity/device/risk

                Technical specifics:
                - VPN without per-session checks is castle-and-moat, not ZT
                  - Exposed RDP to DC is anti-ZT
                  - Microsegmentation example: deny HR VLAN → DC:3389/445 admin paths
                  - Travel + MFA + process is ZT-aligned ops
                  - Conditional Access examples: require MFA for admins, block legacy auth, require compliant device for sensitive apps
                  - Flat network after phishing = lateral movement becomes trivial

                Worked example:
                Trusting 'inside VPN' with no MFA is not Zero Trust.
                Microsegmentation stops HR malware from freely hitting DC admin ports.
                Disabling MFA for executives 'for convenience' breaks ZT / strong AuthN assumptions. Prefer: MFA + travel process + least privilege.

                                More desk clues:
                  - CA examples: MFA for admins, block legacy auth, compliant device for sensitive apps.
                  - Microsegmentation: deny HR VLAN to DC:3389/445 admin paths by default.
                  - Flat network after phishing makes lateral movement trivial.
                  - ZT sticker with internet RDP still open is architecture theater.

                How to answer on the exam:
                1. Reject location-alone trust answers.
                  2. Prefer per-session verify + least privilege.
                  3. Match architecture control to failure class (see PBQ).

                Common trap: 'VPN equals trusted' or disabling MFA for executives for convenience. Near-miss: buying a Zero Trust sticker while 3389 still faces the internet.

                Remember: Authenticate and authorize each session. Location alone is not enough.
                """),
            ("Map control to failure", """
                Where you see this at work: four Boundry failures: open RDP, messy travel grants, legacy-auth BEC, Office→PowerShell. Each needs a different architecture move.

                In Security+ terms, that is choosing architecture controls by failure class.

                Fit map:
                  Open 3389 → remove exposure / VPN + PAM jump
                  Travel inconsistency → ZT / Conditional Access + travel process
                  Legacy-auth inbox rule → disable legacy auth + session/inbox policy
                  Macro→PS → mail gateway + EDR ASR

                Technical specifics:
                - Architecture answers remove paths; dashboards alone do not
                  - Least privilege shrinks what a stolen session can do
                  - svc accounts: no interactive login, no Domain Admin for backup jobs that only need backup rights

                Worked example:
                ALLOW 3389 from internet → remote exposure fix.
                Inbox rule without MFA because legacy auth → identity architecture fix.
                Macro→PS on HR PC → endpoint/mail architecture (ASR), not 'trust the VLAN.'

                How to answer on the exam:
                1. Name the failure class.
                  2. Pick the architecture move that stops that class.
                  3. Avoid detect-only when the path is still open.

                Common trap: near-miss answers that ignore the question's path or control class.

                Remember: Match the control class to the failure class.
                """),
        ],
        [
            _mc("Architecture matching Frankfurt travel + MFA + HR confirm?",
                ["Trust VPN with no checks", "Zero Trust / CA: authn+authz per session + travel process",
                 "Open RDP to DC", "Disable MFA for execs"], 1,
                "Session policy.",
                "Correct. Location on a network is not enough. Per-session policy is the ZT answer. "),
            _mc("Microsegmentation purpose?",
                ["Pretty diagrams only", "Limit east-west paths after phishing",
                 "Delete SIEM", "Replace encryption"], 1,
                "Blast radius.",
                "Correct. Assume the HR PC will get phished someday. Limit east-west. "),
            _mc("Least privilege for svc_veeam means:",
                ["Domain admins for convenience", "Only rights needed for backup jobs, monitored",
                 "No logging", "Internet RDP"], 1,
                "Standing privilege kills you.",
                "Correct. Backup accounts are crown jewels. Convenience admin is the distractor. "),
        ],
        [
            _qz("q_d3_02a", "Zero Trust rejects:",
                ["MFA", "Implicit trust from network location alone", "Tickets", "EDR"], 1,
                "Correct. Verify explicitly. Network location is not a free trust ticket. "),
            _qz("q_d3_02b", "Conditional Access is an example of:",
                ["Physical cage only", "Policy-driven authorization in a ZT-ish design",
                 "Base64", "RTO"], 1,
                "Correct. Session grants. CA is how ZT shows up in cloud identity. "),
            _qz("q_d3_02c", "Flat network risk after phishing:",
                ["No lateral possible", "Easy lateral to higher-value systems",
                 "Automatic encryption of attacker", "CHG success"], 1,
                "Correct. East-west. Flat means phishing becomes lateral quickly. "),
            _qz("q_d3_02d", "Disabling MFA for executives breaks:",
                ["Only toner alerts", "Zero Trust / strong authn assumptions",
                 "Only physical doors", "Hash algorithms"], 1,
                "Correct. Privileged users need more control, not less. "),
        ],
        pbq_zt,
    )

    pbq_rdp = {
        "id": "pbq_d3_rdp",
        "kind": "pick",
        "title": "Fix the exposure",
        "prompt": "ALLOW tcp/3389 from the internet to PROD-DC01. Best architecture fix?",
        "choices": [
            {"id": "fix", "text": "Remove internet RDP; require VPN + MFA + jump/PAM; segment the DC"},
            {"id": "dash", "text": "Add more SIEM dashboards and leave the ALLOW"},
            {"id": "wifi", "text": "Move the DC onto HR Wi-Fi for visibility"},
            {"id": "nolog", "text": "Disable logging so attackers cannot see event IDs"},
        ],
        "answer": "fix",
        "explain": (
            "Correct. Remove the exposure. Detective controls are backup, not the fix. Common trap: more"
            "dashboards while the ALLOW stays. "
        ),
    }

    add(
        "sp_d3_03_infra_network", "d3_architecture", "3.2",
        "Secure infrastructure: network edge", 18,
        ["Firewall", "NIDS", "NIPS", "WAF", "VPN"],
        [
            ("Secure the network path", """
                Infrastructure security for networks means placing controls where traffic flows. A secure baseline starts with deny-by-default on management planes and brokered admin access.

                Where you see this at work: prod DC management should not be reachable from the open internet. Admin work happens through VPN + jump/PAM. East-west traffic from HR to DC admin ports is denied by default.

                In Security+ terms, that is secure network infrastructure: firewall placement, segmentation, secure remote access.

                Network infra beats:
                  1. Deny by default on management planes
                  2. Segment trust tiers (user / server / DC / OT)
                  3. Secure admin access (VPN/MFA/PAM), not inbound RDP
                  4. Monitor ALLOW/DENY with identity context

                Technical specifics:
                - Ports: 3389 RDP, 22 SSH, 445 SMB, 53 DNS, 443 HTTPS
                  - Jump host / PAM reduces standing exposure
                  - NIDS/NIPS are detective/preventive helpers, not a substitute for
                    closing internet RDP to a DC
                  - Prefer explicit source/destination/port on crown-jewel ALLOWs. ANY/ANY is a finding.
                  - Admin paths: VPN (UDP 500/4500 or TLS VPN) + jump/PAM beats inbound TCP 3389.
                  - WAF helps HTTP(S) app classes. It does not close non-HTTP management ports.

                Worked example:
                Best first fix for internet RDP to a DC: remove exposure; VPN/PAM/MFA jump.
                More dashboards only is the near-miss.
                Encrypted VPN without MFA is a honeymoon, not complete remote architecture. Add MFA / CA and brokered admin.

                                More desk clues:
                  - Prefer explicit source/destination/port on crown-jewel ALLOWs. ANY/ANY is a finding.
                  - Admin paths: VPN (UDP 500/4500 or TLS VPN) + jump/PAM beats inbound TCP 3389.
                  - East-west: deny user VLANs to DC admin ports by default; allow only brokers.
                  - When SIEM shows scanner noise, still confirm no unexpected ALLOW appeared beside it.

                How to answer on the exam:
                1. Find the open management path.
                  2. Prefer remove/segment over detect-only.
                  3. Keep admin paths brokered.

                Common trap: leaving 3389 open 'temporarily' without owner, expiry, or compensating broker. Near-miss: equating 'firewall exists' with 'path is closed.'

                Remember: Close management paths. Segment trust tiers.
                """),
            ("Devices and rules that matter", """
                Where you see this at work: a change opens a wide ANY/ANY rule 'to troubleshoot' and never closes it.

                In Security+ terms, that is firewall rule hygiene as infrastructure security.

                Rule hygiene:
                  1. Least privilege ports/sources
                  2. Change ticket + expiry on exceptions
                  3. Log and review high-risk ALLOWs

                Technical specifics:
                - ANY/ANY is an architecture failure waiting for an IOC
                  - Pair rule reviews with asset inventory
                  - Allow-list JUMP-01 / scanners with CHG + firewall/IDS tuning together
                  - When SIEM shows scanner noise, still confirm no unexpected ALLOW appeared beside it

                Worked example:
                Wide troubleshooting ALLOW without expiry becomes permanent exposure. Treat it like a gap. Default-deny with explicit crown-jewel rules is the strong baseline.

                How to answer on the exam:
                1. Prefer specific sources/destinations.
                  2. Demand CHG + expiry.
                  3. Review crown-jewel ALLOWs first.

                Common trap: equating 'firewall exists' with 'path is closed.'

                Remember: A firewall with a bad ALLOW is still an open path.
                """),
            ("801 architecture: SSE, OOB, privilege creep", """
                Where you see this at work: users roam on coffee-shop Wi-Fi. Instead of
                hairpinning all traffic through a single old VPN concentrator, you place
                Security Service Edge (SSE) controls closer to the user: secure web gateway,
                CASB-style SaaS control, and Zero Trust network access for apps. Separately,
                out-of-band (OOB) management keeps admin interfaces off the user data plane.
                Separately, a former project lead still holds Global Admin (privilege creep).

                In Security+ terms, that is managing security architecture on SY0-801:
                Security Service Edge (SSE), out-of-band management, and identity hygiene
                against privilege creep (also watch gMSA / least-privilege service accounts).

                Define before use:
                  - SSE: cloud-delivered edge security services for web, SaaS, and private
                    app access (think secure access service edge security stack without
                    requiring every packet back to HQ)
                  - Out-of-band management: admin path separated from production user traffic
                  - Privilege creep: access accumulates over time beyond the job need
                  - gMSA (Group Managed Service Account): Windows managed service identity
                    with automatic password handling (prefer over static service passwords)

                Technical specifics:
                  - SSE answers often pair with Zero Trust: verify user/device, least app access.
                  - OOB: management VRF/VLAN/jump, not RDP on the same NIC users browse with.
                  - Privilege creep fix: access reviews, JIT/PAM, remove standing Global Admin.
                  - gMSA reduces stale shared service passwords on domain-joined hosts.

                Worked example:
                Contractor finished six months ago but still has Owner on the cloud subscription.
                Class: privilege creep. Architecture/IAM ops answer: remove or time-bound,
                review privileged roles, prefer JIT. Near-miss: "add more SSE logos" without
                removing the standing Owner role.

                How to answer on the exam:
                  1. Match SSE to secure edge access for distributed users/apps.
                  2. Match OOB to separated management planes.
                  3. Match privilege creep to excess standing rights over time.

                Common trap: calling any cloud proxy "SSE" while inbound RDP to a DC remains.
                Near-miss: ignoring privilege creep because the firewall diagram looks modern.

                Remember: SSE secures the edge path. OOB separates admin. Reviews stop creep.
                """),
        ],
        [
            _mc("ALLOW 3389 internet→DC. Best architecture fix?",
                ["More dashboards, keep ALLOW", "Remove internet RDP; VPN+MFA+jump; segment",
                 "HR Wi-Fi for the DC", "Disable logging"], 1,
                "Close the path.",
                "Correct. Domain 3: remove exposure. Dashboards are not the architecture fix. "),
            _mc("NIPS vs NIDS: NIPS adds:",
                ["Only prettier charts", "Inline prevention/block capability",
                 "Physical badges", "CHG text"], 1,
                "Prevention in the path.",
                "Correct. IDS detects; IPS can block. That one word difference is exam gold. "),
            _mc("VPN kill switch purpose on analyst laptop?",
                ["Faster spray", "Avoid cleartext leak if tunnel drops",
                 "Open RDP", "Delete EDR"], 1,
                "Fail closed for remote work.",
                "Correct. Kill switch OFF is a Boundry gap for a reason. Fail closed. "),
            _mc("Former contractor still holds cloud Owner with no review. Best label?",
                ["Successful SSE deployment", "Privilege creep needing removal or JIT review",
                 "Out-of-band management success", "Proof NIDS alone is enough"], 1,
                "Standing rights beyond the job.",
                "Correct. Privilege creep is excess access over time. "
                "Common trap: buying edge tools while Owner stays forever. "
                "Remember: review and remove standing privilege."),
        ],
        [
            _qz("q_d3_03a", "Default-deny firewall is:",
                ["Weak design", "Strong secure-infrastructure baseline",
                 "Only cloud", "Only physical"], 1,
                "Correct. Allow only what you need. Default-deny is baseline strength. "),
            _qz("q_d3_03b", "WAF primarily protects:",
                ["Badge doors", "Web applications at HTTP(S) layer",
                 "Only backups", "Toner"], 1,
                "Correct. App edge. Do not confuse WAF with physical or backup controls. "),
            _qz("q_d3_03c", "Encrypted VPN tunnel without MFA is architecturally:",
                ["Complete remote architecture", "Incomplete: authn too weak for the path",
                 "A honeypot", "RPO"], 1,
                "Correct. Encrypt path + strong identity. Encryption alone is incomplete. "),
            _qz("q_d3_03d", "Allow-listing JUMP-01 belongs with:",
                ["No documentation", "Change control + firewall/IDS tuning",
                 "Deleting 4625", "Opening 3389 to the world"], 1,
                "Correct. Authorized scan hygiene needs tickets and tuning together. "),
            _qz("q_d3_03e", "Security Service Edge (SSE) is best described as:",
                ["A physical cage lock only", "Cloud-delivered edge controls for web/SaaS/app access",
                 "A replacement for all access reviews", "An excuse to open inbound RDP"], 1,
                "Correct. SSE is the secure edge service stack for distributed access. "
                "Common trap: treating SSE as a reason to skip identity hygiene. "
                "Remember: edge controls plus least privilege."),
        ],
        pbq_rdp,
    )

    add(
        "sp_d3_04_infra_endpoint_cloud", "d3_architecture", "3.2",
        "Secure infrastructure: endpoint and cloud", 18,
        ["EDR", "Hardening", "Secure Baseline", "NSG", "Least Privilege"],
        [
            ("Endpoints and cloud control planes", """
                Endpoints and cloud consoles are infrastructure too. Hardening them closes common Domain 2 paths. The control plane is where admins change identity, network, and storage settings.

                Where you see this at work: HR PCs get EDR + ASR. Cloud admin portals require MFA and Conditional Access. Storage accounts are not public 'for convenience.'

                In Security+ terms, that is endpoint hardening and cloud security posture as infrastructure controls.

                Endpoint/cloud map:
                  1. EDR + ASR + disk encryption + patching
                  2. Least local admin
                  3. Cloud: MFA on admins, tight IAM roles, private storage, NSG hygiene
                  4. Secure baselines / CIS-style hardening where used

                Technical specifics:
                - BitLocker for confidentiality at rest on laptops
                  - Cloud misconfig: public blob with payroll exports
                  - Admin consoles are crown jewels equal to DCs
                  - Endpoint desk clues: EDR health, ASR rules, local admin count, BitLocker status, patch age
                  - Cloud desk clues: MFA on Global Admin / Owner roles, PIM/JIT if available, no public storage with sensitive exports
                  - Secrets in repos and chat are infrastructure findings, not style notes

                Worked example:
                Macro path needs endpoint architecture (ASR) plus mail controls.
                Public cloud storage with sensitive exports is an infra misconfig, not 'SaaS magic.'
                Local admin on every HR PC breaks least privilege and turns every phishing click into an easier install path.

                                More desk clues:
                  - Endpoint: EDR health, ASR rules, local admin count, BitLocker status, patch age.
                  - Cloud control plane: MFA on Global Admin / Owner roles, PIM/JIT if available, no public storage with sensitive exports.
                  - Drift check: compare baseline GPO/Intune/ASR to what HR images actually run.
                  - Secrets in repos and chat are infrastructure findings, not style notes.

                How to answer on the exam:
                1. Ask which plane failed: device or cloud control plane.
                  2. Pick hardening that removes that path.
                  3. Keep shared responsibility in mind.

                Common trap: hardening laptops while leaving cloud root keys in a shared chat. Near-miss: BitLocker as the answer when the story is Office→script on an unlocked session.

                Remember: Endpoint and cloud consoles are infrastructure attack surfaces.
                """),
            ("Baseline and drift", """
                Where you see this at work: a golden image had ASR on, but a department image quietly turned it off.

                In Security+ terms, that is configuration baselines and drift as architecture/ops overlap.

                Baseline beats:
                  1. Define required controls
                  2. Deploy consistently
                  3. Detect drift
                  4. Fix with change process

                Technical specifics:
                - Drift check: compare baseline GPO/Intune/ASR to what HR images actually run
                  - Private endpoints / private links keep services off the public internet when the design allows
                  - NSG 0.0.0.0/0:3389 to a domain-joined VM is the same failure class as on-prem internet RDP

                Worked example:
                Golden image Monday, HR laptop Friday with local admin and ASR off = hardening failed. Reopen the baseline ticket. Do not mark done.

                How to answer on the exam:
                1. Ask if the baseline still holds.
                  2. Prefer verify-after-deploy answers.
                  3. Treat cloud NSG exposure like on-prem firewall exposure.

                Common trap: assuming the golden image equals every live laptop forever.

                Remember: Baselines fail when drift is invisible. Measure and fix.
                """),
        ],
        [
            _mc("Architecture control that stops Office→powershell?",
                ["Only more SIEM charts", "EDR ASR / attack surface reduction rules",
                 "Opening RDP", "Disabling MFA"], 1,
                "Endpoint guardrail.",
                "Correct. Prevent the child process. Charts after the fact are not architecture. "),
            _mc("Cloud NSG allowing 0.0.0.0/0:3389 to a domain-joined VM:",
                ["Fine because cloud", "Same class of failure as on-prem internet RDP",
                 "Required for backups", "Physical only"], 1,
                "Shared responsibility.",
                "Correct. Cloud does not forgive open management ports. "),
            _mc("Secure baseline purpose?",
                ["Randomize fonts", "Consistent hardened config across the fleet",
                 "Delete logs", "Disable encryption"], 1,
                "Fleet consistency.",
                "Correct. Reduce drift and weak defaults. That is why baselines exist. "),
        ],
        [
            _qz("q_d3_04a", "Local admin on every HR PC breaks:",
                ["Least privilege architecture", "Only toner", "Only RPO", "DNS"], 0,
                "Correct. Standing privilege. Least privilege fails when everyone is admin. "),
            _qz("q_d3_04b", "Disk encryption belongs in:",
                ["Endpoint/data architecture for lost devices", "Only SOAR",
                 "Only NIDS", "Only CHG jokes"], 0,
                "Correct. Confidentiality at rest for lost/stolen devices. "),
            _qz("q_d3_04c", "Private endpoint idea:",
                ["Expose more public IPs", "Keep service traffic off the public internet when possible",
                 "Disable MFA", "Ignore NSGs"], 1,
                "Correct. Shrink cloud surface. Less public IP exposure. "),
            _qz("q_d3_04d", "Effective control selection means:",
                ["Always pick awareness first", "Pick the control that closes the scenario path",
                 "Always pick honeypots first", "Never use EDR"], 1,
                "Correct. Scenario fit beats favorite tool bias. "),
        ],
    )

    add(
        "sp_d3_05_data_states", "d3_architecture", "3.3",
        "Data protection: states and classification", 17,
        ["Data at Rest", "Data in Transit", "Data in Use", "Classification", "DLP"],
        [
            ("Data in transit, at rest, in use", """
                Data has states: in transit (moving on the network), at rest (stored), and in use (being processed). Controls differ by state. Classification is the label that says how sensitive the data is.

                Where you see this at work: TLS protects the Boundry dashboard in transit. BitLocker protects a stolen laptop at rest. A screen privacy filter and least privilege help data in use on a shared desk.

                In Security+ terms, that is protecting data by state with the matching control type.

                State map:
                  In transit → TLS/VPN/SSH
                  At rest → BitLocker, encrypted backups, encrypted cloud storage
                  In use → access control, DLP endpoints, clean desk / privacy, rights management

                Technical specifics:
                - Hashing is not encryption for confidentiality of contents
                  - Classification labels drive which control is required
                  - BEC forward attacks confidentiality of mail contents (often stored/in-use mail, not a TLS failure)
                  - In transit check: browser TLS, SMTP/TLS, VPN. Cleartext login pages fail this state.
                  - At rest check: BitLocker/FileVault, encrypted backups, encrypted cloud objects.
                  - In use check: who can open the file now (ACL/DLP/rights), not only disk encryption.
                  - Exam near-miss: answering BitLocker when the story is an HTTP password form.

                Worked example:
                Stolen unencrypted laptop = at-rest confidentiality failure.
                HTTP login page = in-transit failure.
                Correct control must match the state the question describes.
                Near-miss: BitLocker for a cleartext web login, or TLS for a stolen unencrypted disk with no network story.

                                More desk clues:
                  - In transit check: browser TLS, SMTP/TLS, VPN. Cleartext login pages fail this state.
                  - At rest check: BitLocker/FileVault, encrypted backups, encrypted cloud objects.
                  - In use check: who can open the file now (ACL/DLP/rights), not only disk encryption.
                  - Exam near-miss: answering BitLocker when the story is an HTTP password form.

                How to answer on the exam:
                1. Name the data state.
                  2. Pick the control for that state.
                  3. Do not answer BitLocker for a TLS question or vice versa.

                Common trap: picking disk encryption when the question is clearly about data in transit. Another near-miss: calling a hash of a password 'encrypting the file at rest.'

                Remember: Match the control to the data state in the question.
                """),
            ("Classification drives control", """
                Where you see this at work: payroll exports get a higher label than the public marketing PDF.

                In Security+ terms, that is data classification as the driver for encryption, DLP, and access rules.

                Classification beats:
                  1. Label sensitivity
                  2. Bind handling rules
                  3. Enforce with technical controls where possible

                Technical specifics:
                - Public vs internal vs confidential vs restricted
                  - Mislabeling causes both overblocking and silent leakage
                  - Confidential payroll CSV in a public share fails classification and technical enforcement together

                Worked example:
                Confidential payroll CSV in a public share is a classification + control failure. Fix the label and the share ACL/encryption, not only one.

                How to answer on the exam:
                1. Find the label/sensitivity clue.
                  2. Ask which state is exposed.
                  3. Pick enforcement that matches.

                Common trap: treating all data as equal so either nothing is encrypted or everything is unusable.

                Remember: Labels without enforcement are posters. Enforcement without labels is guesswork.
                """),
        ],
        [
            _mc("CFO auto-forward to Gmail. Missing strategy?",
                ["Longer screensaver only", "Classification + DLP / external-forward control",
                 "WPA3 on guest only", "Delete SigninLogs"], 1,
                "Sensitive mail leaving.",
                "Correct. Protect data with classification-driven DLP. Screensaver is the distractor. "),
            _mc("TLS on Boundry UI protects which state primarily?",
                ["Data in transit", "Only data at rest on USB", "Physical cages", "RTO"], 0,
                "On the wire.",
                "Correct. TLS is classic data-in-transit protection. "),
            _mc("BitLocker primarily protects:",
                ["Data at rest on the endpoint", "Only SMTP", "Only NIDS", "CHG text"], 0,
                "Disk.",
                "Correct. At rest on the endpoint. Do not relocate BitLocker to SMTP. "),
        ],
        [
            _qz("q_d3_05a", "Classification purpose:",
                ["Decorate folders", "Drive which DLP/handling rules apply",
                 "Open RDP", "Replace MFA"], 1,
                "Correct. Label → control. Classification is not decoration. "),
            _qz("q_d3_05b", "Data in use control example:",
                ["TLS only", "Endpoint DLP blocking paste/upload of sensitive files",
                 "Only cage lock", "Only RPO"], 1,
                "Correct. While the user works. TLS alone is transit, not in-use. "),
            _qz("q_d3_05c", "Encrypted backups address:",
                ["Data at rest confidentiality if media is stolen", "Only spray",
                 "Only physical badges", "Legacy auth"], 0,
                "Correct. Backup media risk is at-rest confidentiality. "),
            _qz("q_d3_05d", "Unclassified finance mail makes DLP:",
                ["Stronger automatically", "Weaker / noisier because rules lack labels",
                 "Unnecessary", "A honeypot"], 1,
                "Correct. Labels matter. Unlabeled sensitive mail weakens DLP. "),
        ],
    )

    pbq_dlp = {
        "id": "pbq_d3_dlp",
        "kind": "pick",
        "title": "Data control gap",
        "prompt": (
            "Third external forward of finance mail this quarter. No DLP rule on external "
            "auto-forward. Legacy auth still on. What architecture package do you recommend?"
        ),
        "choices": [
            {"id": "pkg", "text": "Classify finance data, block/alert external forwards, disable legacy auth, CA for risky mail clients"},
            {"id": "poster", "text": "Only a new poster; leave forwards and legacy auth"},
            {"id": "rdp", "text": "Expose OWA on 3389 for easier admin"},
            {"id": "nolog", "text": "Turn off mailbox audit to reduce noise"},
        ],
        "answer": "pkg",
        "explain": (
            "Correct. Data architecture + identity protocol debt together. Posters alone fail weekly."
            "Stack classification, forward control, and modern auth. Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d3_06_dlp_encryption", "d3_architecture", "3.3",
        "DLP and encryption placement", 17,
        ["DLP", "Encryption", "Rights Management", "Tokenization"],
        [
            ("Stop data leaving the wrong way", """
                DLP means data loss prevention: controls that detect or block sensitive data leaving approved channels. Encryption hides contents with keys. They answer different failure modes and often work together.

                Where you see this at work: DLP alerts when payroll CSVs upload to personal cloud. Encryption protects the laptop disk and the HTTPS session. An external mail forward rule is a DLP/policy miss waiting to happen.

                In Security+ terms, that is DLP and encryption as complementary data protections.

                Fit map:
                  Encryption → confidentiality if device/channel is taken
                  DLP → stop or alert on policy-violating exfil paths
                  Rights management / access control → who can open the file
                  Tokenization/masking → reduce exposure in lower environments

                Technical specifics:
                - External forward-all needs block/alert controls, not only TLS
                  - TLS does not stop a logged-in attacker from forwarding mail
                  - BitLocker does not stop upload from an unlocked session
                  - TLS does not stop a valid session from creating an external forward rule.
                  - DLP/forward controls and encryption answer different failure modes. Often you need both.
                  - Keys beside ciphertext (backup key on the same share) fail 'appropriate use.'

                Worked example:
                Confirmed BEC forward: revoke sessions + remove rule + DLP/forward policy. TLS alone would not have stopped the forward.
                Near-miss: answering BitLocker for a mailbox forward question, or DLP for a stolen cleartext disk with no upload story.

                                More desk clues:
                  - TLS does not stop a valid session from creating an external forward rule.
                  - BitLocker does not stop upload from an unlocked logged-in laptop.
                  - DLP/forward controls and encryption answer different failure modes. Often you need both.
                  - Keys beside ciphertext (backup key on the same share) fail "appropriate use."

                How to answer on the exam:
                1. Ask if the problem is hiding bits or stopping an exfil path.
                  2. Pick encryption vs DLP accordingly.
                  3. Often you need both layers.

                Common trap: answering BitLocker for a mailbox forward question, or DLP for a stolen cleartext disk with no upload story.

                Remember: Encryption hides. DLP polices where data may go.
                """),
            ("Keys and appropriate use", """
                Where you see this at work: backups are 'encrypted' but the key sits on the same share as the backup.

                In Security+ terms, that is appropriate cryptographic use includes key management.

                Key beats:
                  1. Separate keys from ciphertext when possible
                  2. Manage cert lifetimes
                  3. Prefer platform-managed keys over chat-pasted secrets

                Technical specifics:
                - Expired certs create trust/availability friction
                  - Hard-coded API keys in repos are data/crypto failures
                  - Base64 is encoding, not encryption. Do not call a Base64 blob an encrypted backup.

                Worked example:
                Encrypted backup with key beside it is weak appropriate-use. Fix key custody. Calling any Base64 blob 'encrypted backups' is the classic near-miss.

                How to answer on the exam:
                1. Check where keys live.
                  2. Check cert validity.
                  3. Prefer managed secrets.

                Common trap: calling any Base64 blob 'encrypted backups.'

                Remember: Appropriate crypto means right control, right place, managed keys.
                """),
        ],
        [
            _mc("Best control for unauthorized external auto-forward of finance mail?",
                ["Only longer passwords on Wi-Fi", "DLP / transport rule blocking or alerting forwards",
                 "Open RDP", "Disable accounting"], 1,
                "Stop the path.",
                "Correct. DLP/mail rules are the fit. Longer Wi-Fi passwords miss the mail path. "),
            _mc("Rights management helps when:",
                ["You need control after the file leaves the mailbox", "You want open 3389",
                 "You delete SIEM", "You skip MFA"], 0,
                "Persistent protection.",
                "Correct. Control after send. That is the rights-management purpose. "),
            _mc("Encrypting backups but leaving laptop disks clear means:",
                ["Full data architecture", "Gap for lost/stolen endpoints",
                 "Perfect ZT", "Only a CHG issue"], 1,
                "Place encryption where devices live.",
                "Correct. Gap for endpoints. Partial encryption is still a gap. "),
        ],
        [
            _qz("q_d3_06a", "DLP purpose:",
                ["Detect/prevent sensitive data leaving approved channels", "Replace firewalls",
                 "Open VPN", "Set RTO"], 0,
                "Correct. Exfil control. DLP does not replace firewalls. "),
            _qz("q_d3_06b", "Encryption in transit classic tool:",
                ["TLS/VPN", "Only badge", "Only honeypot", "Only AUP"], 0,
                "Correct. Wire protection. TLS/VPN are the classics. "),
            _qz("q_d3_06c", "Tokenization is useful to:",
                ["Expose PANs widely", "Reduce sensitive cleartext in app databases",
                 "Disable EDR", "Ignore classification"], 1,
                "Correct. Minimize secret sprawl in apps. "),
            _qz("q_d3_06d", "Architecture package after BEC forwards:",
                ["Poster only", "DLP forward control + disable legacy auth + CA",
                 "More internet RDP", "Delete mailbox audit"], 1,
                "Correct. Stack controls. Poster-only is incomplete. "),
        ],
        pbq_dlp,
    )

    add(
        "sp_d3_07_resilience_ha", "d3_architecture", "3.4",
        "Resilience: HA and site strategy", 17,
        ["High Availability", "Failover", "Hot Site", "Warm Site", "Cold Site"],
        [
            ("Stay up when parts fail", """
                Resilience means the system keeps serving through failures. High availability (HA) uses redundant components so one failure does not take everything down. A single point of failure is one component whose loss takes down the service.

                Where you see this at work: two DNS servers, clustered load balancers, and a secondary site for critical apps. A single jump host with no spare is a resilience gap for admin access.

                In Security+ terms, that is resilience and high availability architecture.

                Resilience beats:
                  1. Redundancy (no single point of failure for critical paths)
                  2. Failover tested, not theoretical
                  3. Diversity where common-mode failure matters
                  4. Capacity for failover load

                Technical specifics:
                - HA ≠ backups. HA keeps service up; backups restore data.
                  - Ransomware-proofing needs offline/immutable backups, not only HA pairs
                  - VPN concentrator HA matters for remote work continuity
                  - Name the SPOF: one VPN concentrator, one DNS, one MFA provider, one jump host
                  - HA pairs that share the same ransomware-accessible backup identity still fail recovery
                  - Hot / warm / cold sites trade cost vs how ready the alternate site is

                Worked example:
                Dual firewalls in HA help availability of the path. They do not replace offline backups if both see the same ransomware-encrypted share logic.
                Warm site: partial readiness between hot (live twin) and cold (empty-ish). Pick site type to match RTO.

                                More desk clues:
                  - Name the single point of failure: one VPN concentrator, one DNS, one MFA provider, one jump host.
                  - HA pairs that share the same ransomware-accessible backup identity still fail recovery.
                  - Test failover under load assumptions. Untested failover is documentation, not control.
                  - Break-glass accounts need monitoring so resilience does not become a backdoor.

                How to answer on the exam:
                1. Ask if the question wants uptime or recoverability.
                  2. HA for uptime; backups/DR for restore.
                  3. Look for single points of failure.

                Common trap: calling HA a substitute for backups, or backups a substitute for removing single points of failure. Near-miss: untested failover diagrams presented as resilience.

                Remember: HA keeps the lights on. Backups bring data back.
                """),
            ("Design for failure", """
                Where you see this at work: the only MFA/SMS provider dies and nobody can authenticate.

                In Security+ terms, that is avoiding brittle dependencies in resilience design.

                Brittleness checks:
                  1. Auth path redundancy / break-glass
                  2. Power / ISP diversity for critical sites
                  3. Documented failover owners

                Technical specifics:
                - Break-glass accounts with tight monitoring
                  - Test failover on a schedule
                  - Redundant ISP links mainly help availability of connectivity
                  - Backup admin that is Domain Admin everywhere: compromise of the backup plane kills resilience

                Worked example:
                Single SMS provider with no alternate auth factor is an availability risk disguised as an MFA success story. Prefer alternate factors + monitored break-glass.

                How to answer on the exam:
                1. Hunt single points of failure.
                  2. Prefer tested failover.
                  3. Keep break-glass controlled and logged.

                Common trap: untested failover diagrams presented as resilience.

                Remember: If failover was never tested, it is a hope, not a control.
                """),
        ],
        [
            _mc("Hot site vs cold site: hot is:",
                ["Cheapest and slowest", "Most ready / fastest failover, highest cost",
                 "Only a poster", "Only encryption"], 1,
                "Readiness costs money.",
                "Correct. Pick site type to match RTO. Hot costs more because it is ready. "),
            _mc("HA cluster purpose:",
                ["Guaranteed zero ransomware", "Keep service available through component failure",
                 "Replace IR", "Open RDP"], 1,
                "Availability engineering.",
                "Correct. HA survives component failure. It does not guarantee zero ransomware. "),
            _mc("Why resilience is on the security exam outline?",
                ["Fonts", "Attacks and failures both kill availability; restore is part of defense",
                 "Only physical", "Only CHG"], 1,
                "CIA availability.",
                "Correct. Restore is part of defense, not an optional ops hobby. "),
        ],
        [
            _qz("q_d3_07a", "Warm site roughly means:",
                ["Fully live twin always", "Partial readiness between hot and cold",
                 "No power", "Only SaaS"], 1,
                "Correct. Middle tier. Not fully live, not empty space only. "),
            _qz("q_d3_07b", "Failover testing matters because:",
                ["Paper plans always work", "Untested HA is a hope, not a control",
                 "It opens 3389", "It disables MFA"], 1,
                "Correct. Prove it. Untested HA is hope. "),
            _qz("q_d3_07c", "Redundant ISP links mainly help:",
                ["Confidentiality of Gmail", "Availability of connectivity",
                 "Hashing", "Legacy auth"], 1,
                "Correct. Path diversity for availability. "),
            _qz("q_d3_07d", "Security risk if backup admin is domain admin everywhere:",
                ["None", "Compromise of backup plane = kill resilience",
                 "Faster patching only", "Better DLP"], 1,
                "Correct. Protect the recovery path or resilience dies with it. "),
        ],
    )

    add(
        "sp_d3_08_backup_rto", "d3_architecture", "3.4",
        "Backups, RTO, and RPO", 18,
        ["RTO", "RPO", "Backup", "Immutable Backup", "Restore Test"],
        [
            ("RTO, RPO, and backups that work", """
                RTO means recovery time objective: how quickly you must restore service. RPO means recovery point objective: how much data loss (in time) you can tolerate. Backups are how you often meet those numbers. Immutable means the copy cannot be altered or deleted for a retention window.

                Where you see this at work: finance says RTO 4 hours and RPO 15 minutes for the billing DB. That means more than nightly backups. You also need offline/immutable copies so ransomware cannot encrypt the only backup.

                In Security+ terms, that is backup strategy tied to RTO/RPO, including ransomware-resistant copies.

                Backup beats:
                  1. Match frequency to RPO
                  2. Match restore process to RTO
                  3. Keep offline / immutable / out-of-band copies
                  4. Encrypt backups and protect keys
                  5. Test restores

                Technical specifics:
                - 3-2-1 style thinking: multiple copies, media types, offsite/offline
                  - Backups connected with domain admin credentials are easy ransomware targets
                  - Hot/warm/cold sites trade cost vs RTO
                  - Nightly backup alone fails a 15-minute RPO. You need frequent snapshots or continuous replication that match the RPO number.
                  - Online-only backups fail ransomware scenarios even if HA looks pretty.
                  - Separate backup identity from Domain Admin. Monitor it.
                  - Encrypt backups and keep keys off the same share as the ciphertext.

                Worked example:
                Nightly backup alone fails a 15-minute RPO.
                Online-only backups fail ransomware scenarios even if HA looks pretty.
                Question: RPO 15 minutes, only nightly jobs. Answer: backup frequency does not meet RPO. Near-miss: 'we have Veeam' without frequency or offline copy.

                                More desk clues:
                  - Nightly-only jobs fail a 15-minute RPO. Match frequency to the RPO number.
                  - Separate backup identity from Domain Admin. Monitor the recovery plane.
                  - Encrypt backups; keep keys off the same share as the ciphertext.
                  - If restore takes 18h and RTO is 4h, you failed RTO. Fix process or site readiness.

                How to answer on the exam:
                1. Read RTO vs RPO carefully.
                  2. Match backup design to both.
                  3. Prefer answers that include test + offline copy for ransomware questions.

                Common trap: mixing RTO and RPO, or assuming HA clusters meet RPO without backup frequency. Near-miss: green backup jobs without restore proof.

                Remember: RPO = how much data loss. RTO = how fast back up. Test restores.
                """),
            ("Restore is the control", """
                Where you see this at work: backups succeed every night; nobody has restored billing in eighteen months.

                In Security+ terms, that is tested restore as part of resilience, not optional paperwork.

                Restore beats:
                  1. Schedule restore tests
                  2. Measure actual time vs RTO
                  3. Document who runs the restore

                Technical specifics:
                - A backup you cannot restore is not a control
                  - Include identity/cloud SaaS export strategies where relevant
                  - If restore test takes 18h and RTO is 4h, you failed RTO. Fix process, parallelism, or site readiness.
                  - Immutable / offline copy purpose: survive online encryption of primary and connected backup planes

                Worked example:
                Untested backups are a resilience gap even when green checkmarks fill the dashboard. 'We have Veeam' is not enough after ransomware if copies are online-only and identity is shared with Domain Admin.

                How to answer on the exam:
                1. Prefer tested restore answers.
                  2. Tie to RTO evidence.
                  3. Keep ransomware offline copies in the plan.

                Common trap: green backup jobs without restore proof.

                Remember: The control is a restore that meets RTO/RPO, not a job status icon.
                """),
        ],
        [
            _mc("Why is 'we have Veeam' not enough after ransomware?",
                ["Restores must be tested and backup identity protected",
                 "Veeam always needs internet RDP open to restore",
                 "Resilience is only about physical site distance",
                 "Never isolate a host if any backup job exists"], 0,
                "svc_veeam is a crown jewel.",
                "Correct. A product name is not recovery. You need proven restores and a "
                "protected backup plane so ransomware cannot wipe the only copy. "
                "Common trap: treating green backup jobs as proof. "
                "Remember: backup identity is a crown jewel."),
            _mc("RPO of 1 hour means:",
                ["Service must be fully up within 1 hour",
                 "Up to about 1 hour of data loss is tolerable",
                 "Users must complete MFA every hour",
                 "Patches must install every hour"], 1,
                "Data loss window.",
                "Correct. RTO is time-to-recover. RPO is data-loss tolerance. "
                "Common trap: swapping those two. Remember: RPO drives how often you back up."),
            _mc("Immutable backups help against:",
                ["Printer toner shortages as the main concern",
                 "Ransomware deleting or encrypting backups",
                 "Phishing posters in the lobby as the fix",
                 "Legacy authentication alone as the answer"], 1,
                "Protect recovery media.",
                "Correct. Immutable copies survive online ransomware aimed at backup targets. "
                "Common trap: assuming online backups alone are safe. "
                "Remember: protect the recovery media."),
        ],
        [
            _qz("q_d3_08a", "RTO measures:",
                ["Max acceptable downtime to restore service", "Password length",
                 "VLAN count", "Only classification"], 0,
                "Correct. Time to recover. That is the RTO definition. "),
            _qz("q_d3_08b", "Restore test frequency should be:",
                ["Never", "On a defined cadence: not only on disaster day",
                 "Only when RDP is open", "Only after firing analysts"], 1,
                "Correct. Prove restores on a cadence, not only during the outage. "),
            _qz("q_d3_08c", "Offline / immutable copy purpose:",
                ["Faster spray", "Survive online ransomware of backup targets",
                 "Disable EDR", "Skip MFA"], 1,
                "Correct. Air gap-ish protection for recovery media. "),
            _qz("q_d3_08d", "Backup account with broad admin and weak monitoring is:",
                ["Hardened", "A resilience and security failure waiting to happen",
                 "Required by ZT", "A honeypot"], 1,
                "Correct. Protect recovery identity or you lose the restore path. "),
            _qz("q_d3_08e", "RPO of 15 minutes with only nightly backups means:",
                ["RPO is met", "Backup frequency does not meet RPO",
                 "RTO is automatically zero", "HA alone fixes RPO"], 1,
                "Correct. RPO sets how much data loss you can tolerate. Nightly backups "
                "cannot meet a 15-minute RPO. Common trap: mixing RTO with RPO. "
                "Remember: RPO drives backup frequency."),
        ],
    )

    add(
        "sp_d3_09_continuity_testing", "d3_architecture", "3.4",
        "Continuity testing and capacity", 17,
        ["BCP", "DR Testing", "Tabletop", "Capacity Planning"],
        [
            ("Continuity plans you actually rehearse", """
                Business continuity keeps critical business functions running. Disaster recovery brings IT services back after a major disruption. Both need testing. A tabletop is a discussion exercise. A restore or failover test proves the technical path.

                Where you see this at work: tabletop for ransomware, technical failover test for the VPN pair, and a phone tree that still has last year's on-call list.

                In Security+ terms, that is BCP/DR testing and after-action improvement.

                Testing types:
                  1. Tabletop (talk through decisions)
                  2. Walkthrough / simulation
                  3. Parallel / full interrupt tests where justified
                  4. After-action: fix gaps, update contacts, retest

                Technical specifics:
                - Continuity depends on identity, comms, and backups working together
                  - Stale contact lists fail real incidents
                  - Scope tests to critical processes first
                  - Tabletop finds decision/people gaps. Technical failover finds restore/path gaps. You need both over time.
                  - Include critical vendors/MSPs when they sit on the restore or comms path.
                  - After-action items need owner + due date or the exercise was theater.

                Worked example:
                A beautiful DR binder with no test in two years is weaker than a messy plan that was tabletopped last quarter and patched.
                Tabletop vs restore test: tabletop stresses decisions; restore test stresses technical restore time vs RTO.

                                More desk clues:
                  - Tabletop finds decision/people gaps. Technical failover finds restore/path gaps. You need both over time.
                  - Update contact trees after every exercise. Stale on-call lists fail first.
                  - Include critical vendors/MSPs when they sit on the restore or comms path.
                  - After-action items need owner + due date or the exercise was theater.

                How to answer on the exam:
                1. Ask if the plan was tested.
                  2. Prefer answers that include lessons learned + updates.
                  3. Separate BCP (business) from DR (IT) when the question does.

                Common trap: assuming documentation alone equals continuity. Near-miss: closing an exercise with 'went fine' when payments approval failed.

                Remember: Untested continuity plans fail on contact lists and restore steps first.
                """),
            ("After-action loop", """
                Where you see this at work: failover worked, but finance could not approve emergency spend because the approver was unreachable.

                In Security+ terms, that is improving continuity from exercise findings.

                Loop:
                  1. Run test
                  2. Record gaps
                  3. Assign owners
                  4. Update plan
                  5. Retest critical gaps

                Technical specifics:
                - Include vendors/MSPs in exercises when they are on the critical path
                  - Keep break-glass and comms out-of-band options
                  - Update contact trees after every exercise
                  - After a real BEC, continuity docs should update with lessons and owners

                Worked example:
                Exercise finding without an owner is theater. Assign and due-date it.
                Best evidence of DR readiness: measured restore/failover on a cadence, not a binder never opened.

                How to answer on the exam:
                1. Look for owner + update + retest.
                  2. Reject binder-only answers.
                  3. Include people process, not only servers.

                Common trap: closing an exercise with 'went fine' when payments approval failed.

                Remember: Continuity is a loop: test, fix, retest.
                """),
        ],
        [
            _mc("Tabletop exercise primarily validates:",
                ["Only disk encryption math", "People/process decisions under a scenario",
                 "Only NSG syntax", "Toner levels"], 1,
                "Human path.",
                "Correct. Tabletops find decision gaps before ransomware night. "),
            _mc("If restore test takes 18h and RTO is 4h:",
                ["You are fine", "You have a resilience gap to fix or re-negotiate",
                 "Disable backups", "Open RDP"], 1,
                "Measure vs target.",
                "Correct. Honest metrics beat logo slides. Gap to fix or re-negotiate. "),
            _mc("Capacity planning for backups prevents:",
                ["All phishing", "Failed backups / incomplete retention from growth",
                 "Need for MFA", "Need for tickets"], 1,
                "Jobs silently fail when full.",
                "Correct. Growth without capacity planning breaks silent backup jobs. "),
        ],
        [
            _qz("q_d3_09a", "BCP purpose:",
                ["Keep critical business functions through disruption", "Open 3389",
                 "Replace hashing", "Disable SIEM"], 0,
                "Correct. Business first. Continuity protects critical functions. "),
            _qz("q_d3_09b", "Best evidence of DR readiness:",
                ["A binder never opened", "Dated restore test results vs RTO/RPO",
                 "More dashboards only", "Verbal vendor promise"], 1,
                "Correct. Proof. Dated restore results beat binders and promises. "),
            _qz("q_d3_09c", "After a real BEC, continuity docs should:",
                ["Stay frozen forever", "Update with lessons and owners",
                 "Be deleted", "Blame only the analyst"], 1,
                "Correct. Living documents. Update with lessons. "),
            _qz("q_d3_09d", "Tabletop vs restore test:",
                ["Identical", "Tabletop stresses decisions; restore test stresses tech recovery",
                 "Neither useful", "Only for OT"], 1,
                "Correct. Different proofs. Know which one the stem is asking for. "),
        ],
    )
