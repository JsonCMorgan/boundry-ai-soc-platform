"""Option 1 depth packs for Domains 3–5.

Executed by tools/_apply_option1_depth.py with body/put/DEPTH already in globals.
Do not import this module directly.
"""

# ---------------------------------------------------------------------------
# DOMAIN 3
# ---------------------------------------------------------------------------
put(
    "sp_d3_01_arch_models",
    17,
    [
        (
            "Where the control lives",
            body(
                orient=(
                    "Architecture models describe where systems run: on-premises, cloud, or "
                    "hybrid. Shared responsibility means the provider and customer each own "
                    "parts of security. You still own identity, data, and configuration even "
                    "when the provider owns hardware."
                ),
                work=(
                    "Boundry runs Entra ID (cloud identity), an on-prem domain controller, and "
                    "SaaS mail. A cloud marketing slide does not make legacy auth safe."
                ),
                formal="on-prem, IaaS, PaaS, SaaS, hybrid, and shared responsibility.",
                beats=(
                    "Model map:\n"
                    "  On-prem: you own more of the stack (DC, firewall, backups)\n"
                    "  IaaS: provider hosts hardware; you harden VMs/NSGs/OS\n"
                    "  PaaS: less OS duty; still identity, data, app config\n"
                    "  SaaS: vendor runs the app; you still own identity, DLP, admin roles\n"
                    "  Hybrid: mix; hunt the plane where the session lived"
                ),
                tech=(
                    "  - SaaS mail BEC still needs identity + forwarding/DLP controls\n"
                    "  - IaaS open NSG 3389 is primarily the customer's problem\n"
                    "  - Hybrid: SigninLogs and on-prem 462x as needed\n"
                    "  - OT/ICS and fragile legacy: segment + compensate, not internet RDP"
                ),
                worked=(
                    "SaaS mail still requires you to own identity, forwarding/DLP, admin roles. "
                    "IaaS VM with open NSG 3389 is yours: customer network/OS config. "
                    "Hybrid Entra + on-prem DC means hunt both cloud and on-prem sources."
                ),
                how=(
                    "  1. Name the model in the question.\n"
                    "  2. Ask which slice the customer still owns.\n"
                    "  3. Pick logs/controls for that slice."
                ),
                trap="'shared responsibility means the customer owns nothing' or 'cloud provider patches Hyper-V so legacy auth is fine.'",
                remember="Architecture model drives which logs you open and which controls you still owe.",
            ),
        ),
        (
            "ICS / leftover systems",
            body(
                work=(
                    "a vendor wants internet RDP to a fragile OT panel 'because the plant "
                    "software is old.'"
                ),
                formal="compensating controls and segmentation for systems you cannot patch like a laptop.",
                beats=(
                    "Fragile system beats:\n"
                    "  1. Segment away from the open internet\n"
                    "  2. Prefer brokered access (jump/VPN/PAM)\n"
                    "  3. Document compensating controls with owner and review"
                ),
                tech=(
                    "  - On-prem DC exposure is critical: identity store + lateral potential\n"
                    "  - Talk-track: pick sources by where the identity/session lived"
                ),
                worked=(
                    "OT/ICS gets compensating controls and segmentation, not internet RDP "
                    "because the vendor said so."
                ),
                how=(
                    "  1. Identify fragile/legacy constraints.\n"
                    "  2. Prefer path removal + segment.\n"
                    "  3. Reject 'cloud/SaaS means zero customer duty.'"
                ),
                trap="treating on-prem crown jewels as if they were low-value SaaS toys.",
                remember="Provider ownership never deletes your identity duty.",
            ),
        ),
    ],
)

put(
    "sp_d3_02_zero_trust_arch",
    18,
    [
        (
            "Ops definition that passes the exam",
            body(
                orient=(
                    "Zero Trust rejects implicit trust from network location alone. You "
                    "authenticate and authorize every session, assume breach, use least "
                    "privilege, and validate continuously."
                ),
                work=(
                    "CEO travel login is allowed because MFA passed and HR confirmed travel, "
                    "not because 'they are on VPN.' HR PCs should not talk to DC admin ports "
                    "by default."
                ),
                formal="Zero Trust and microsegmentation as architecture, not a product sticker.",
                beats=(
                    "ZT pillars in practice:\n"
                    "  1. Verify explicitly (AuthN + AuthZ per session)\n"
                    "  2. Least privilege\n"
                    "  3. Assume breach / limit blast radius\n"
                    "  4. Microsegmentation: separate trust tiers and admin paths\n"
                    "  5. Conditional Access wraps policy around identity/device/risk"
                ),
                tech=(
                    "  - VPN without per-session checks is castle-and-moat, not ZT\n"
                    "  - Exposed RDP to DC is anti-ZT\n"
                    "  - Microsegmentation example: deny HR VLAN → DC:3389/445 admin paths\n"
                    "  - Travel + MFA + process is ZT-aligned ops"
                ),
                worked=(
                    "Trusting 'inside VPN' with no MFA is not Zero Trust. "
                    "Microsegmentation stops HR malware from freely hitting DC admin ports."
                ),
                how=(
                    "  1. Reject location-alone trust answers.\n"
                    "  2. Prefer per-session verify + least privilege.\n"
                    "  3. Match architecture control to failure class (see PBQ)."
                ),
                trap="'VPN equals trusted' or disabling MFA for executives for convenience.",
                remember="Authenticate and authorize each session. Location alone is not enough.",
            ),
        ),
        (
            "Map control to failure",
            body(
                work=(
                    "four Boundry failures: open RDP, messy travel grants, legacy-auth BEC, "
                    "Office→PowerShell. Each needs a different architecture move."
                ),
                formal="choosing architecture controls by failure class.",
                beats=(
                    "Fit map:\n"
                    "  Open 3389 → remove exposure / VPN + PAM jump\n"
                    "  Travel inconsistency → ZT / Conditional Access + travel process\n"
                    "  Legacy-auth inbox rule → disable legacy auth + session/inbox policy\n"
                    "  Macro→PS → mail gateway + EDR ASR"
                ),
                tech=(
                    "  - Architecture answers remove paths; dashboards alone do not\n"
                    "  - Least privilege shrinks what a stolen session can do"
                ),
                worked=(
                    "ALLOW 3389 from internet → remote exposure fix. "
                    "Inbox rule without MFA because legacy auth → identity architecture fix."
                ),
                how=(
                    "  1. Name the failure class.\n"
                    "  2. Pick the architecture move that stops that class.\n"
                    "  3. Avoid detect-only when the path is still open."
                ),
                trap="near-miss answers that ignore the question's path or control class.",
                remember="Match the control class to the failure class.",
            ),
        ),
    ],
)

put(
    "sp_d3_03_infra_network",
    17,
    [
        (
            "Secure the network path",
            body(
                orient="Infrastructure security for networks means placing controls where traffic flows.",
                work=(
                    "prod DC management should not be reachable from the open internet. Admin "
                    "work happens through VPN + jump/PAM. East-west traffic from HR to DC admin "
                    "ports is denied by default."
                ),
                formal="secure network infrastructure: firewall placement, segmentation, secure remote access.",
                beats=(
                    "Network infra beats:\n"
                    "  1. Deny by default on management planes\n"
                    "  2. Segment trust tiers (user / server / DC / OT)\n"
                    "  3. Secure admin access (VPN/MFA/PAM), not inbound RDP\n"
                    "  4. Monitor ALLOW/DENY with identity context"
                ),
                tech=(
                    "  - Ports: 3389 RDP, 22 SSH, 445 SMB, 53 DNS, 443 HTTPS\n"
                    "  - Jump host / PAM reduces standing exposure\n"
                    "  - NIDS/NIPS are detective/preventive helpers, not a substitute for\n"
                    "    closing internet RDP to a DC"
                ),
                worked=(
                    "Best first fix for internet RDP to a DC: remove exposure; VPN/PAM/MFA jump. "
                    "More dashboards only is the near-miss."
                ),
                how=(
                    "  1. Find the open management path.\n"
                    "  2. Prefer remove/segment over detect-only.\n"
                    "  3. Keep admin paths brokered."
                ),
                trap="leaving 3389 open 'temporarily' without owner, expiry, or compensating broker.",
                remember="Close management paths. Segment trust tiers.",
            ),
        ),
        (
            "Devices and rules that matter",
            body(
                work="a change opens a wide ANY/ANY rule 'to troubleshoot' and never closes it.",
                formal="firewall rule hygiene as infrastructure security.",
                beats=(
                    "Rule hygiene:\n"
                    "  1. Least privilege ports/sources\n"
                    "  2. Change ticket + expiry on exceptions\n"
                    "  3. Log and review high-risk ALLOWs"
                ),
                tech=(
                    "  - ANY/ANY is an architecture failure waiting for an IOC\n"
                    "  - Pair rule reviews with asset inventory"
                ),
                worked=(
                    "Wide troubleshooting ALLOW without expiry becomes permanent exposure. "
                    "Treat it like a gap."
                ),
                how=(
                    "  1. Prefer specific sources/destinations.\n"
                    "  2. Demand CHG + expiry.\n"
                    "  3. Review crown-jewel ALLOWs first."
                ),
                trap="equating 'firewall exists' with 'path is closed.'",
                remember="A firewall with a bad ALLOW is still an open path.",
            ),
        ),
    ],
)

put(
    "sp_d3_04_infra_endpoint_cloud",
    17,
    [
        (
            "Endpoints and cloud control planes",
            body(
                orient="Endpoints and cloud consoles are infrastructure too. Hardening them closes common Domain 2 paths.",
                work=(
                    "HR PCs get EDR + ASR. Cloud admin portals require MFA and Conditional "
                    "Access. Storage accounts are not public 'for convenience.'"
                ),
                formal="endpoint hardening and cloud security posture as infrastructure controls.",
                beats=(
                    "Endpoint/cloud map:\n"
                    "  1. EDR + ASR + disk encryption + patching\n"
                    "  2. Least local admin\n"
                    "  3. Cloud: MFA on admins, tight IAM roles, private storage, NSG hygiene\n"
                    "  4. Secure baselines / CIS-style hardening where used"
                ),
                tech=(
                    "  - BitLocker for confidentiality at rest on laptops\n"
                    "  - Cloud misconfig: public blob with payroll exports\n"
                    "  - Admin consoles are crown jewels equal to DCs"
                ),
                worked=(
                    "Macro path needs endpoint architecture (ASR) plus mail controls. "
                    "Public cloud storage with sensitive exports is an infra misconfig, not 'SaaS magic.'"
                ),
                how=(
                    "  1. Ask which plane failed: device or cloud control plane.\n"
                    "  2. Pick hardening that removes that path.\n"
                    "  3. Keep shared responsibility in mind."
                ),
                trap="hardening laptops while leaving cloud root keys in a shared chat.",
                remember="Endpoint and cloud consoles are infrastructure attack surfaces.",
            ),
        ),
        (
            "Baseline and drift",
            body(
                work="a golden image had ASR on, but a department image quietly turned it off.",
                formal="configuration baselines and drift as architecture/ops overlap.",
                beats=(
                    "Baseline beats:\n"
                    "  1. Define required controls\n"
                    "  2. Deploy consistently\n"
                    "  3. Detect drift\n"
                    "  4. Fix with change process"
                ),
                tech=(
                    "  - Drift on legacy auth or ASR is an architecture debt ticket\n"
                    "  - Inventory which images/OU policies actually apply"
                ),
                worked=(
                    "If policy says ASR on but half of HR is off, governance and architecture "
                    "both failed until drift is fixed."
                ),
                how=(
                    "  1. Compare required vs actual.\n"
                    "  2. Treat silent off-switches as gaps.\n"
                    "  3. Repair with owned change."
                ),
                trap="assuming the golden image is still what production runs.",
                remember="Baselines only help if drift is detected and fixed.",
            ),
        ),
    ],
)

put(
    "sp_d3_05_data_states",
    17,
    [
        (
            "Data in transit, at rest, in use",
            body(
                orient=(
                    "Data has states: in transit (moving on the network), at rest (stored), "
                    "and in use (being processed). Controls differ by state."
                ),
                work=(
                    "TLS protects the Boundry dashboard in transit. BitLocker protects a stolen "
                    "laptop at rest. A screen privacy filter and least privilege help data in use "
                    "on a shared desk."
                ),
                formal="protecting data by state with the matching control type.",
                beats=(
                    "State map:\n"
                    "  In transit → TLS/VPN/SSH\n"
                    "  At rest → BitLocker, encrypted backups, encrypted cloud storage\n"
                    "  In use → access control, DLP endpoints, clean desk / privacy, rights management"
                ),
                tech=(
                    "  - Hashing is not encryption for confidentiality of contents\n"
                    "  - Classification labels drive which control is required\n"
                    "  - BEC forward attacks confidentiality of mail contents (often 'in use'/stored mail)"
                ),
                worked=(
                    "Stolen unencrypted laptop = at-rest confidentiality failure. "
                    "HTTP login page = in-transit failure. "
                    "Correct control must match the state the question describes."
                ),
                how=(
                    "  1. Name the data state.\n"
                    "  2. Pick the control for that state.\n"
                    "  3. Do not answer BitLocker for a TLS question or vice versa."
                ),
                trap="picking disk encryption when the question is clearly about data in transit.",
                remember="Match the control to the data state in the question.",
            ),
        ),
        (
            "Classification drives control",
            body(
                work="payroll exports get a higher label than the public marketing PDF.",
                formal="data classification as the driver for encryption, DLP, and access rules.",
                beats=(
                    "Classification beats:\n"
                    "  1. Label sensitivity\n"
                    "  2. Bind handling rules\n"
                    "  3. Enforce with technical controls where possible"
                ),
                tech=(
                    "  - Public vs internal vs confidential vs restricted\n"
                    "  - Mislabeling causes both overblocking and silent leakage"
                ),
                worked=(
                    "Confidential payroll CSV in a public share is a classification + control failure."
                ),
                how=(
                    "  1. Find the label/sensitivity clue.\n"
                    "  2. Ask which state is exposed.\n"
                    "  3. Pick enforcement that matches."
                ),
                trap="treating all data as equal so either nothing is encrypted or everything is unusable.",
                remember="Labels without enforcement are posters. Enforcement without labels is guesswork.",
            ),
        ),
    ],
)

put(
    "sp_d3_06_dlp_encryption",
    17,
    [
        (
            "Stop data leaving the wrong way",
            body(
                orient=(
                    "DLP means data loss prevention: controls that detect or block sensitive "
                    "data leaving approved channels. Encryption hides contents with keys."
                ),
                work=(
                    "DLP alerts when payroll CSVs upload to personal cloud. Encryption protects "
                    "the laptop disk and the HTTPS session. An external mail forward rule is a "
                    "DLP/policy miss waiting to happen."
                ),
                formal="DLP and encryption as complementary data protections.",
                beats=(
                    "Fit map:\n"
                    "  Encryption → confidentiality if device/channel is taken\n"
                    "  DLP → stop or alert on policy-violating exfil paths\n"
                    "  Rights management / access control → who can open the file\n"
                    "  Tokenization/masking → reduce exposure in lower environments"
                ),
                tech=(
                    "  - External forward-all needs block/alert controls, not only TLS\n"
                    "  - TLS does not stop a logged-in attacker from forwarding mail\n"
                    "  - BitLocker does not stop upload from an unlocked session"
                ),
                worked=(
                    "Confirmed BEC forward: revoke sessions + remove rule + DLP/forward policy. "
                    "TLS alone would not have stopped the forward."
                ),
                how=(
                    "  1. Ask if the problem is hiding bits or stopping an exfil path.\n"
                    "  2. Pick encryption vs DLP accordingly.\n"
                    "  3. Often you need both layers."
                ),
                trap="answering BitLocker for a mailbox forward question, or DLP for a stolen cleartext disk with no upload story.",
                remember="Encryption hides. DLP polices where data may go.",
            ),
        ),
        (
            "Keys and appropriate use",
            body(
                work="backups are 'encrypted' but the key sits on the same share as the backup.",
                formal="appropriate cryptographic use includes key management.",
                beats=(
                    "Key beats:\n"
                    "  1. Separate keys from ciphertext when possible\n"
                    "  2. Manage cert lifetimes\n"
                    "  3. Prefer platform-managed keys over chat-pasted secrets"
                ),
                tech=(
                    "  - Expired certs create trust/availability friction\n"
                    "  - Hard-coded API keys in repos are data/crypto failures"
                ),
                worked=(
                    "Encrypted backup with key beside it is weak appropriate-use. Fix key custody."
                ),
                how=(
                    "  1. Check where keys live.\n"
                    "  2. Check cert validity.\n"
                    "  3. Prefer managed secrets."
                ),
                trap="calling any Base64 blob 'encrypted backups.'",
                remember="Appropriate crypto means right control, right place, managed keys.",
            ),
        ),
    ],
)

put(
    "sp_d3_07_resilience_ha",
    16,
    [
        (
            "Stay up when parts fail",
            body(
                orient=(
                    "Resilience means the system keeps serving through failures. High availability "
                    "(HA) uses redundant components so one failure does not take everything down."
                ),
                work=(
                    "two DNS servers, clustered load balancers, and a secondary site for critical "
                    "apps. A single jump host with no spare is a resilience gap for admin access."
                ),
                formal="resilience and high availability architecture.",
                beats=(
                    "Resilience beats:\n"
                    "  1. Redundancy (no single point of failure for critical paths)\n"
                    "  2. Failover tested, not theoretical\n"
                    "  3. Diversity where common-mode failure matters\n"
                    "  4. Capacity for failover load"
                ),
                tech=(
                    "  - HA ≠ backups. HA keeps service up; backups restore data.\n"
                    "  - Ransomware-proofing needs offline/immutable backups, not only HA pairs\n"
                    "  - VPN concentrator HA matters for remote work continuity"
                ),
                worked=(
                    "Dual firewalls in HA help availability of the path. They do not replace "
                    "offline backups if both see the same ransomware-encrypted share logic."
                ),
                how=(
                    "  1. Ask if the question wants uptime or recoverability.\n"
                    "  2. HA for uptime; backups/DR for restore.\n"
                    "  3. Look for single points of failure."
                ),
                trap="calling HA a substitute for backups, or backups a substitute for removing single points of failure.",
                remember="HA keeps the lights on. Backups bring data back.",
            ),
        ),
        (
            "Design for failure",
            body(
                work="the only MFA/SMS provider dies and nobody can authenticate.",
                formal="avoiding brittle dependencies in resilience design.",
                beats=(
                    "Brittleness checks:\n"
                    "  1. Auth path redundancy / break-glass\n"
                    "  2. Power / ISP diversity for critical sites\n"
                    "  3. Documented failover owners"
                ),
                tech=(
                    "  - Break-glass accounts with tight monitoring\n"
                    "  - Test failover on a schedule"
                ),
                worked=(
                    "Single SMS provider with no alternate auth factor is an availability risk "
                    "disguised as an MFA success story."
                ),
                how=(
                    "  1. Hunt single points of failure.\n"
                    "  2. Prefer tested failover.\n"
                    "  3. Keep break-glass controlled and logged."
                ),
                trap="untested failover diagrams presented as resilience.",
                remember="If failover was never tested, it is a hope, not a control.",
            ),
        ),
    ],
)

put(
    "sp_d3_08_backup_rto",
    17,
    [
        (
            "RTO, RPO, and backups that work",
            body(
                orient=(
                    "RTO means recovery time objective: how quickly you must restore service. "
                    "RPO means recovery point objective: how much data loss (in time) you can "
                    "tolerate. Backups are how you often meet those numbers."
                ),
                work=(
                    "finance says RTO 4 hours and RPO 15 minutes for the billing DB. That means "
                    "more than nightly backups. You also need offline/immutable copies so "
                    "ransomware cannot encrypt the only backup."
                ),
                formal="backup strategy tied to RTO/RPO, including ransomware-resistant copies.",
                beats=(
                    "Backup beats:\n"
                    "  1. Match frequency to RPO\n"
                    "  2. Match restore process to RTO\n"
                    "  3. Keep offline / immutable / out-of-band copies\n"
                    "  4. Encrypt backups and protect keys\n"
                    "  5. Test restores"
                ),
                tech=(
                    "  - 3-2-1 style thinking: multiple copies, media types, offsite/offline\n"
                    "  - Backups connected with domain admin credentials are easy ransomware targets\n"
                    "  - Hot/warm/cold sites trade cost vs RTO"
                ),
                worked=(
                    "Nightly backup alone fails a 15-minute RPO. "
                    "Online-only backups fail ransomware scenarios even if HA looks pretty."
                ),
                how=(
                    "  1. Read RTO vs RPO carefully.\n"
                    "  2. Match backup design to both.\n"
                    "  3. Prefer answers that include test + offline copy for ransomware stems."
                ),
                trap="mixing RTO and RPO, or assuming HA clusters meet RPO without backup frequency.",
                remember="RPO = how much data loss. RTO = how fast back up. Test restores.",
            ),
        ),
        (
            "Restore is the control",
            body(
                work="backups succeed every night; nobody has restored billing in eighteen months.",
                formal="tested restore as part of resilience, not optional paperwork.",
                beats=(
                    "Restore beats:\n"
                    "  1. Schedule restore tests\n"
                    "  2. Measure actual time vs RTO\n"
                    "  3. Document who runs the restore"
                ),
                tech=(
                    "  - A backup you cannot restore is not a control\n"
                    "  - Include identity/cloud SaaS export strategies where relevant"
                ),
                worked=(
                    "Untested backups are a resilience gap even when green checkmarks fill the dashboard."
                ),
                how=(
                    "  1. Prefer tested restore answers.\n"
                    "  2. Tie to RTO evidence.\n"
                    "  3. Keep ransomware offline copies in the plan."
                ),
                trap="green backup jobs without restore proof.",
                remember="The control is a restore that meets RTO/RPO, not a job status icon.",
            ),
        ),
    ],
)

put(
    "sp_d3_09_continuity_testing",
    16,
    [
        (
            "Continuity plans you actually rehearse",
            body(
                orient=(
                    "Business continuity keeps critical business functions running. Disaster "
                    "recovery brings IT services back after a major disruption. Both need testing."
                ),
                work=(
                    "tabletop for ransomware, technical failover test for the VPN pair, and a "
                    "phone tree that still has last year's on-call list."
                ),
                formal="BCP/DR testing and after-action improvement.",
                beats=(
                    "Testing types:\n"
                    "  1. Tabletop (talk through decisions)\n"
                    "  2. Walkthrough / simulation\n"
                    "  3. Parallel / full interrupt tests where justified\n"
                    "  4. After-action: fix gaps, update contacts, retest"
                ),
                tech=(
                    "  - Continuity depends on identity, comms, and backups working together\n"
                    "  - Stale contact lists fail real incidents\n"
                    "  - Scope tests to critical processes first"
                ),
                worked=(
                    "A beautiful DR binder with no test in two years is weaker than a messy "
                    "plan that was tabletopped last quarter and patched."
                ),
                how=(
                    "  1. Ask if the plan was tested.\n"
                    "  2. Prefer answers that include lessons learned + updates.\n"
                    "  3. Separate BCP (business) from DR (IT) when the question does."
                ),
                trap="assuming documentation alone equals continuity.",
                remember="Untested continuity plans fail on contact lists and restore steps first.",
            ),
        ),
        (
            "After-action loop",
            body(
                work="failover worked, but finance could not approve emergency spend because the approver was unreachable.",
                formal="improving continuity from exercise findings.",
                beats=(
                    "Loop:\n"
                    "  1. Run test\n"
                    "  2. Record gaps\n"
                    "  3. Assign owners\n"
                    "  4. Update plan\n"
                    "  5. Retest critical gaps"
                ),
                tech=(
                    "  - Include vendors/MSPs in exercises when they are on the critical path\n"
                    "  - Keep break-glass and comms out-of-band options"
                ),
                worked=(
                    "Exercise finding without an owner is theater. Assign and due-date it."
                ),
                how=(
                    "  1. Look for owner + update + retest.\n"
                    "  2. Reject binder-only answers.\n"
                    "  3. Include people process, not only servers."
                ),
                trap="closing an exercise with 'went fine' when payments approval failed.",
                remember="Continuity is a loop: test, fix, retest.",
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# DOMAIN 4 (ops-heavy: keep packs dense but one primary + one drill section)
# ---------------------------------------------------------------------------
put(
    "sp_d4_01_harden_compute",
    17,
    [
        (
            "What you touch on a ticket",
            body(
                orient="Hardening means reducing attack surface on compute: OS, VMs, containers, and images.",
                work=(
                    "you remove local admin from HR laptops, enable EDR/ASR, patch, disable "
                    "unused services, and lock down PowerShell logging on sensitive jump hosts."
                ),
                formal="compute hardening techniques used in day-to-day ops.",
                beats=(
                    "Compute harden list:\n"
                    "  1. Patch / update\n"
                    "  2. Remove unused roles/services\n"
                    "  3. Least privilege / no standing local admin\n"
                    "  4. EDR + ASR + application allow-preference where used\n"
                    "  5. Secure baselines and disk encryption\n"
                    "  6. Host firewall on, unnecessary ports closed"
                ),
                tech=(
                    "  - Office→script ASR blocks common malware children\n"
                    "  - Jump hosts get stricter hardening than kiosk PCs\n"
                    "  - Containers: minimal images, no root by default, scan images"
                ),
                worked=(
                    "After Invoice.xlsm, hardening that matters: ASR + least admin + EDR, not "
                    "wallpaper policies."
                ),
                how=(
                    "  1. Name the compute surface.\n"
                    "  2. Pick the harden control that closes the path in the question.\n"
                    "  3. Prefer prevent before detect-only."
                ),
                trap="answering 'install more wallpaper' or 'disable EDR to speed the PC.'",
                remember="Hardening removes paths before the alert fires.",
            ),
        ),
        (
            "Do the job",
            body(
                work="PBQ-style: match each failure to a harden move.",
                formal="applying hardening that matches the scenario.",
                beats=(
                    "Quick fits:\n"
                    "  Macro→PS → ASR / block internet macros\n"
                    "  Standing local admin → remove / PAM\n"
                    "  Unpatched VPN client → patch/replace\n"
                    "  Cleartext laptop → BitLocker"
                ),
                tech=(
                    "  - Change-control hardening pushes; verify after deploy\n"
                    "  - Document exceptions with owner/date"
                ),
                worked=(
                    "If excel→powershell still works after 'hardening,' you hardened the wrong control."
                ),
                how=(
                    "  1. Match control to path.\n"
                    "  2. Verify the control actually applied.\n"
                    "  3. Keep exceptions owned."
                ),
                trap="claiming hardened when the original execution path still works.",
                remember="Verify hardening. Drift undoes baselines.",
            ),
        ),
    ],
)

put(
    "sp_d4_02_harden_network_app",
    16,
    [
        (
            "Close management paths",
            body(
                orient="Network and application hardening closes remote and app-layer paths.",
                work=(
                    "deny inbound 3389 from internet, require MFA VPN, turn off unused HTTP "
                    "verbs/features, and put WAF/rate limits in front of public apps where appropriate."
                ),
                formal="network and application hardening in operations.",
                beats=(
                    "Network/app harden:\n"
                    "  1. Management plane not on the open internet\n"
                    "  2. TLS on apps; no cleartext admin\n"
                    "  3. Remove default accounts/pages\n"
                    "  4. Input validation / secure headers / patch apps\n"
                    "  5. API keys not in mobile apps or repos"
                ),
                tech=(
                    "  - WAF helps some web abuse; it does not forgive open RDP to a DC\n"
                    "  - Disable legacy app auth that bypasses MFA"
                ),
                worked=(
                    "Primary harden for internet RDP: remove it. "
                    "App default admin/password pages are app hardening failures."
                ),
                how=(
                    "  1. Find exposed service.\n"
                    "  2. Close or broker access.\n"
                    "  3. Patch and remove defaults."
                ),
                trap="WAF-only answer for a non-HTTP management port exposure.",
                remember="Close management paths first. Then harden the app features you must expose.",
            ),
        ),
        (
            "App layer",
            body(
                work="a public form reflects script tags; another app still has /admin with vendor default password.",
                formal="application security hygiene as ops hardening.",
                beats=(
                    "App beats: patch, remove defaults, least privilege DB accounts, secrets management."
                ),
                tech=(
                    "  - Secrets in Git are an ops finding, not a style note\n"
                    "  - Rate limiting helps spray against login endpoints"
                ),
                worked=(
                    "Default creds on a public admin page are both Domain 2 and Domain 4 material."
                ),
                how=(
                    "  1. Remove defaults.\n"
                    "  2. Patch.\n"
                    "  3. Protect secrets and auth endpoints."
                ),
                trap="calling secure coding optional because a SIEM exists.",
                remember="Exposed apps need harden + monitor, not monitor alone.",
            ),
        ),
    ],
)

put(
    "sp_d4_03_asset_management",
    17,
    [
        (
            "Why svc_backup2 at 03:14 is a crisis",
            body(
                orient="Asset management means knowing what you have, who owns it, and what privilege it holds.",
                work=(
                    "a new local admin svc_backup2 appears overnight with no ticket. Inventory "
                    "did not even list that service account as approved."
                ),
                formal="hardware/software/data asset management and account hygiene.",
                beats=(
                    "Asset beats:\n"
                    "  1. Inventory devices, apps, accounts, data stores\n"
                    "  2. Owner for each critical asset\n"
                    "  3. Lifecycle: join / move / leave / decommission\n"
                    "  4. Remove ghost admins and stale VPN accounts"
                ),
                tech=(
                    "  - Unexpected privileged account = integrity + asset control failure\n"
                    "  - Shadow IT appears when inventory is weak\n"
                    "  - Decommission should revoke certs, VPN, and group membership"
                ),
                worked=(
                    "svc_backup2 at 03:14 with no ticket: escalate. Missing from inventory makes "
                    "it worse, not better."
                ),
                how=(
                    "  1. Ask if the asset/account should exist.\n"
                    "  2. Check owner and ticket.\n"
                    "  3. Prefer lifecycle answers for stale access."
                ),
                trap="ignoring unknown admins because 'backups need admin.'",
                remember="You cannot defend assets you do not know you have.",
            ),
        ),
        (
            "Lifecycle",
            body(
                work="contractor laptop and VPN still active 60 days after offboarding.",
                formal="asset and identity lifecycle operations.",
                beats=(
                    "Offboard checklist: account disable, MFA devices, VPN, groups, laptop return/wipe, tokens."
                ),
                tech=(
                    "  - Orphaned privileged service accounts are crown-jewel debt\n"
                    "  - CMDB/inventory accuracy is a control input"
                ),
                worked=(
                    "Stale contractor VPN is an asset/identity lifecycle miss and a remote vector."
                ),
                how=(
                    "  1. Look for joiners/movers/leavers clues.\n"
                    "  2. Pick revoke/decommission answers.\n"
                    "  3. Tie ownership to inventory."
                ),
                trap="keeping access 'just in case' with no owner or review date.",
                remember="Lifecycle failures become Domain 2 vectors.",
            ),
        ),
    ],
)

put(
    "sp_d4_04_vuln_lifecycle",
    17,
    [
        (
            "Scan is not done",
            body(
                orient="Vulnerability management is a lifecycle: discover, prioritize, remediate, verify, exception.",
                work=(
                    "Nessus finishes, tickets open, owners patch or accept risk with date, then "
                    "rescans prove closure. A critical on a DC beats a low on a lab printer."
                ),
                formal="vulnerability management lifecycle operations.",
                beats=(
                    "Lifecycle:\n"
                    "  1. Discover (scan / agent / inventory)\n"
                    "  2. Prioritize (severity + asset value + exploitability)\n"
                    "  3. Remediate (patch / config fix / compensate)\n"
                    "  4. Verify (rescan)\n"
                    "  5. Exception with owner and review if needed"
                ),
                tech=(
                    "  - CVSS helps prioritize; asset context can override a medium on a DC\n"
                    "  - Misconfigs without CVE still enter the same lifecycle\n"
                    "  - Exceptions are not infinite silence"
                ),
                worked=(
                    "Scan without tickets/owners is incomplete. "
                    "Exception without expiry is a governance failure."
                ),
                how=(
                    "  1. Do not stop at 'scanned.'\n"
                    "  2. Prioritize by risk, not only by color.\n"
                    "  3. Verify closure."
                ),
                trap="closing criticals as 'accepted' with no owner, compensating control, or date.",
                remember="Vulnerability management ends at verified fix or owned exception.",
            ),
        ),
        (
            "Exceptions",
            body(
                work="legacy OT box cannot patch; you segment and monitor with a 90-day review.",
                formal="owned compensating exceptions inside vuln management.",
                beats=(
                    "Exception needs: reason, compensating control, owner, review date, approver."
                ),
                tech=(
                    "  - Internet RDP to DC should almost never be an accepted exception\n"
                    "  - Prefer architecture fix over paperwork"
                ),
                worked=(
                    "Documented segment+monitor for unpatchable OT can be valid. "
                    "Hallway yes for DC RDP is not."
                ),
                how=(
                    "  1. Prefer remediate.\n"
                    "  2. If except, demand compensating + date.\n"
                    "  3. Reject silent risk."
                ),
                trap="treating exceptions as permanent wallpaper.",
                remember="Exceptions expire or they become culture.",
            ),
        ),
    ],
)

put(
    "sp_d4_05_vuln_scan_context",
    16,
    [
        (
            "Better findings",
            body(
                orient="Scan context means knowing what you scanned, with what creds, and whether CHG explains the noise.",
                work=(
                    "JUMP-01 authenticated scan under CHG-512 vs unauthenticated internet noise "
                    "vs a scan that accidentally hit OT during production."
                ),
                formal="vulnerability scanning with authorization, scope, and safety.",
                beats=(
                    "Context beats:\n"
                    "  1. Authorized scope + window\n"
                    "  2. Credentialed vs uncredentialed tradeoffs\n"
                    "  3. Asset criticality in prioritization\n"
                    "  4. Safe scanning for fragile systems"
                ),
                tech=(
                    "  - Credentialed scans find missing patches better; protect scanner creds\n"
                    "  - Match scanner identity in SIEM to avoid false incident pages\n"
                    "  - OT/ICS: careful passive or vendor-approved methods"
                ),
                worked=(
                    "CHG-512 + JUMP-01 match = authorized activity context. "
                    "Scanning fragile OT with aggressive plugins without approval is an ops miss."
                ),
                how=(
                    "  1. Check authorization/scope.\n"
                    "  2. Use asset context in priority.\n"
                    "  3. Do not confuse scanner traffic with attackers without identity checks."
                ),
                trap="escalating known scanner IPs with matching CHG as APT.",
                remember="Scanner context saves shifts. Safety protects fragile systems.",
            ),
        ),
        (
            "Safety",
            body(
                work="someone runs a full aggressive scan against the plant network at noon.",
                formal="safe scanning practices.",
                beats=(
                    "Safety: approve scope, rate limits, avoid peak on fragile hosts, stop on adverse impact."
                ),
                tech=(
                    "  - Production DC scans still need change windows when disruptive\n"
                    "  - Document scanner allow-lists with the same ticket"
                ),
                worked=(
                    "Adverse impact without a stop plan fails both safety and change management."
                ),
                how=(
                    "  1. Look for approval and safety cues.\n"
                    "  2. Prefer controlled scanning answers.\n"
                    "  3. Keep CHG linkage."
                ),
                trap="unscoped scanning because 'security said so.'",
                remember="Authorized and safe beats loud and reckless.",
            ),
        ),
    ],
)

put(
    "sp_d4_06_alerting_queue",
    18,
    [
        (
            "Single pane vs right pane",
            body(
                orient=(
                    "Alerting and monitoring means collecting signals and working a queue. A "
                    "single pane of glass is one console view. The right pane is the source that "
                    "actually explains the alert."
                ),
                work=(
                    "SIEM fires Failed Logon Burst. You do not stare at a pretty dashboard. You "
                    "open SigninLogs/4625, check for success, check CHG, then contain or FP with notes."
                ),
                formal="alert triage workflow: prioritize, validate, escalate, document.",
                beats=(
                    "Queue beats:\n"
                    "  1. Prioritize by severity + asset + path open?\n"
                    "  2. Validate true positive vs FP/CHG\n"
                    "  3. Contain when needed\n"
                    "  4. Ticket with evidence\n"
                    "  5. Tune noisy rules with change control"
                ),
                tech=(
                    "  - Alert ≠ incident until validated\n"
                    "  - Correlation rules need thresholds that match reality\n"
                    "  - SOAR can enrich; humans still gate destructive actions"
                ),
                worked=(
                    "30-user spray alert: block/rate-limit source, hunt success, ticket. "
                    "JUMP-01+CHG: document FP. Do not treat them identically."
                ),
                how=(
                    "  1. Read severity and asset.\n"
                    "  2. Validate with the right source.\n"
                    "  3. Act, then document."
                ),
                trap="closing high-severity crown-jewel path alerts as noise because the queue is long.",
                remember="Work the queue by path and asset, not by who yelled last.",
            ),
        ),
        (
            "Boundry habit",
            body(
                work="alert → source → contain → ticket, in that order when execution or BEC is live.",
                formal="SOC operating rhythm for Domain 4.",
                beats=(
                    "Habit: do not write a novel before containment when malware is running."
                ),
                tech=(
                    "  - Enrichment first is fine if it is seconds, not hours\n"
                    "  - Document enough for the next analyst"
                ),
                worked=(
                    "Encoded PowerShell alert: isolate before composing a five-page essay."
                ),
                how=(
                    "  1. Live threat → contain first.\n"
                    "  2. Ambiguous → validate fast.\n"
                    "  3. Always leave a ticket trail."
                ),
                trap="analysis paralysis while the host encrypts shares.",
                remember="Alert to source to contain to ticket.",
            ),
        ),
    ],
)

put(
    "sp_d4_07_siem_tools",
    17,
    [
        (
            "Tool roles",
            body(
                orient=(
                    "SIEM aggregates and correlates logs. EDR focuses on endpoints. SOAR "
                    "automates repeatable response steps. Know which tool answers which question."
                ),
                work=(
                    "identity spray → SIEM/SigninLogs. excel→powershell → EDR. auto-enrich "
                    "WHOIS + open ticket → SOAR. Firewall ALLOW hunt → firewall + SIEM."
                ),
                formal="monitoring tool roles and when to use each.",
                beats=(
                    "Tool map:\n"
                    "  SIEM: correlation, history, multi-source\n"
                    "  EDR: process tree, isolate, host IOCs\n"
                    "  NDR/firewall: network path/ALLOW/DROP\n"
                    "  Identity logs: AuthN patterns\n"
                    "  SOAR: automate enrich/notify/contain with guardrails"
                ),
                tech=(
                    "  - Wrong tool answers are classic near-misses\n"
                    "  - Use SPL/KQL habits for aggregations (count by src_ip)\n"
                    "  - Retention matters for investigations"
                ),
                worked=(
                    "Parent/child malware: EDR first. "
                    "30-user failures from one IP: identity/SIEM aggregation first."
                ),
                how=(
                    "  1. Ask what evidence you need.\n"
                    "  2. Pick the tool that holds that evidence.\n"
                    "  3. Correlate across tools when needed."
                ),
                trap="using only firewall logs for a mailbox forward BEC.",
                remember="Pick the tool that holds the evidence the question needs.",
            ),
        ),
        (
            "Do the job CTAs",
            body(
                work="Boundry CTAs: SPL Learn, KQL Learn, SOAR Lab, Shift Sim.",
                formal="practicing tool use as part of ops learning.",
                beats=(
                    "Practice map: identity hunts in SPL/KQL, containment playbooks in SOAR, queue reps in Shift Sim."
                ),
                tech=(
                    "  - Tool skill without triage judgment still fails interviews\n"
                    "  - Judgment without tool paths fails exams that ask for sources"
                ),
                worked=(
                    "Say: I aggregate failures by source IP in SIEM, then confirm host process trees in EDR."
                ),
                how=(
                    "  1. Name tool + purpose.\n"
                    "  2. Name next pivot.\n"
                    "  3. Keep ticket evidence."
                ),
                trap="brand-name dropping without saying what evidence you pull.",
                remember="Purpose first, product second.",
            ),
        ),
    ],
)

put(
    "sp_d4_08_tune_capabilities",
    16,
    [
        (
            "Tune, don't just watch",
            body(
                orient="Enhancing capabilities means tuning rules, adding detections, and closing coverage gaps on purpose.",
                work=(
                    "Failed Logon Burst is too noisy on scanner nights, so you exclude JUMP-01 "
                    "with CHG linkage. You add a detection for external forward rule creation."
                ),
                formal="modifying enterprise detection/prevention capabilities with change discipline.",
                beats=(
                    "Tune beats:\n"
                    "  1. Measure false positives / false negatives\n"
                    "  2. Narrow allow-lists carefully\n"
                    "  3. Add detections for missed techniques\n"
                    "  4. Change-control the tune\n"
                    "  5. Re-verify with test cases"
                ),
                tech=(
                    "  - Excluding a whole /8 forever is how you go blind\n"
                    "  - Detection engineering pairs with threat intel / incidents\n"
                    "  - Preventive tunes (ASR, CA) need stakeholder verify"
                ),
                worked=(
                    "Good tune: scanner identity exclusion documented in CHG. "
                    "Bad tune: disable the spray rule because it is noisy."
                ),
                how=(
                    "  1. Prefer narrow exceptions.\n"
                    "  2. Document and verify.\n"
                    "  3. Never 'fix' noise by turning off crown-jewel detections."
                ),
                trap="disabling a noisy rule that also catches real spray.",
                remember="Tune with evidence and ownership. Do not blind yourself.",
            ),
        ),
        (
            "Change discipline",
            body(
                work="someone edits a SIEM rule in prod with no ticket and no peer review.",
                formal="change management applied to detection content.",
                beats=(
                    "Detection changes need: reason, peer review when possible, rollback, test."
                ),
                tech=(
                    "  - Version detections when you can\n"
                    "  - Keep a break-glass path for urgent blocks with after-action ticket"
                ),
                worked=(
                    "Undocumented rule edit that drops 3389 alerts is an ops failure even if meant well."
                ),
                how=(
                    "  1. Demand ticket/reason.\n"
                    "  2. Prefer reversible tunes.\n"
                    "  3. Test after change."
                ),
                trap="cowboy tuning without rollback.",
                remember="Detection content is production. Treat it like production.",
            ),
        ),
    ],
)

put(
    "sp_d4_09_iam_ops",
    17,
    [
        (
            "Daily IAM, not slides",
            body(
                orient="IAM operations means running identity day to day: joiners/movers/leavers, MFA, roles, reviews.",
                work=(
                    "disable accounts on termination day, require MFA for remote admin, review "
                    "Entra privileged roles monthly, and kill legacy auth that skips prompts."
                ),
                formal="identity and access management operations.",
                beats=(
                    "IAM ops map:\n"
                    "  1. Provision / deprovision promptly\n"
                    "  2. MFA and Conditional Access\n"
                    "  3. Least privilege / JIT where possible\n"
                    "  4. Access reviews\n"
                    "  5. Service account hygiene"
                ),
                tech=(
                    "  - Privileged role standing forever is an ops debt\n"
                    "  - Passwordless/Windows Hello can strengthen AuthN when adopted well\n"
                    "  - Break-glass accounts: monitored, rarely used, tightly controlled"
                ),
                worked=(
                    "BEC aftermath IAM ops: revoke sessions, reset, disable legacy auth, review "
                    "mailbox permissions and privileged roles."
                ),
                how=(
                    "  1. Look for lifecycle and privilege clues.\n"
                    "  2. Prefer least privilege + MFA answers.\n"
                    "  3. Separate AuthN vs AuthZ still."
                ),
                trap="shared admin passwords in a spreadsheet as 'ops pragmatism.'",
                remember="IAM ops closes the paths Domain 2 keeps exploiting.",
            ),
        ),
        (
            "Privilege",
            body(
                work="domain admin used for daily email. Service account has interactive logon and admin everywhere.",
                formal="privileged access operations.",
                beats=(
                    "Privilege beats: separate admin accounts, PAM/JIT, no daily email on DA, monitor privileged groups."
                ),
                tech=(
                    "  - 4672 / privileged logon monitoring where applicable\n"
                    "  - Tiered admin model ideas (user vs workstation vs DC tiers)"
                ),
                worked=(
                    "Daily-driver domain admin is an IAM ops failure waiting for phishing."
                ),
                how=(
                    "  1. Separate privileges.\n"
                    "  2. Monitor privileged use.\n"
                    "  3. Time-bound standing access."
                ),
                trap="more privilege to 'save time' without monitoring.",
                remember="Standing privilege is a latent incident.",
            ),
        ),
    ],
)

put(
    "sp_d4_10_automation_soar",
    17,
    [
        (
            "Automate the repeatable",
            body(
                orient=(
                    "SOAR means security orchestration, automation, and response. It stitches "
                    "tools together and automates repeatable steps. Humans still approve "
                    "destructive actions."
                ),
                work=(
                    "playbook auto-enriches spray IPs, opens a ticket, and suggests block. A "
                    "human clicks approve before firewall changes. Isolate host may be automated "
                    "for high-confidence EDR with guardrails."
                ),
                formal="automation and orchestration with human gates.",
                beats=(
                    "SOAR beats:\n"
                    "  1. Automate enrich / notify / ticket\n"
                    "  2. Gate high-impact contain\n"
                    "  3. Measure time saved and error rate\n"
                    "  4. Keep playbooks under change control"
                ),
                tech=(
                    "  - Bad automation: auto-disable VIP accounts on every travel FP\n"
                    "  - Good automation: enrich + consistent ticket fields + optional contain\n"
                    "  - Runbooks/playbooks should match IR phases"
                ),
                worked=(
                    "Auto-block every foreign MFA success without context creates availability "
                    "outages. Enrich + human gate is safer."
                ),
                how=(
                    "  1. Automate toil first.\n"
                    "  2. Gate destructive steps.\n"
                    "  3. Prefer consistent evidence packs."
                ),
                trap="fully automatic account wipe on every anomaly with no confidence check.",
                remember="Automate the repeatable. Gate the irreversible.",
            ),
        ),
        (
            "Failure mode",
            body(
                work="playbook loops and opens 200 duplicate tickets overnight.",
                formal="safe automation design and failure handling.",
                beats=(
                    "Failure beats: idempotency, rate limits, dead-letter handling, kill switch for playbooks."
                ),
                tech=(
                    "  - Test in staging when possible\n"
                    "  - Monitor automation like a production app"
                ),
                worked=(
                    "A runaway playbook is an availability and trust incident inside the SOC."
                ),
                how=(
                    "  1. Look for human gate + rollback.\n"
                    "  2. Reject untested destructive automation.\n"
                    "  3. Keep audit logs of automated actions."
                ),
                trap="SOAR as excuse to remove analysts entirely on day one.",
                remember="Automation without guardrails becomes the incident.",
            ),
        ),
    ],
)

put(
    "sp_d4_11_ir_phases",
    18,
    [
        (
            "The sequence",
            body(
                orient=(
                    "Incident response phases are a standard order of work. CompTIA-style "
                    "sequences commonly include preparation, detection/analysis, containment, "
                    "eradication, recovery, and lessons learned."
                ),
                work=(
                    "malware on HR PC: detect in EDR, contain by isolate, eradicate persistence, "
                    "recover to known-good, then lessons learned that add ASR."
                ),
                formal="IR phase order and what belongs in each phase.",
                beats=(
                    "Phase map:\n"
                    "  1. Preparation (before the fire)\n"
                    "  2. Detection and analysis\n"
                    "  3. Containment\n"
                    "  4. Eradication\n"
                    "  5. Recovery\n"
                    "  6. Lessons learned / post-incident"
                ),
                tech=(
                    "  - Contain before deep forensics when spread is active\n"
                    "  - Eradication examples: remove rule, disable legacy auth, delete persistence\n"
                    "  - Recovery: restore, reimage, re-enable with monitoring\n"
                    "  - Preparation: playbooks, contacts, tooling, training"
                ),
                worked=(
                    "Leaving a host online to 'analyze overnight' skips containment. Wrong phase order."
                ),
                how=(
                    "  1. Identify the phase the question asks for.\n"
                    "  2. Do not jump to lessons learned before contain.\n"
                    "  3. Preparation answers only when the story is before the incident."
                ),
                trap="recovery before containment, or lessons-learned posters as the first response to live BEC.",
                remember="Detect → contain → eradicate → recover → learn. Prep before all of it.",
            ),
        ),
        (
            "Preparation",
            body(
                work="no call tree, no isolate authority, EDR licenses expired.",
                formal="preparation as the phase that makes the other phases possible.",
                beats=(
                    "Prep checklist: roles, playbooks, tooling health, evidence handling, management buy-in."
                ),
                tech=(
                    "  - Tabletop exercises are preparation\n"
                    "  - Break-glass and legal/comms contacts belong here"
                ),
                worked=(
                    "If analysts cannot isolate without a three-day debate, preparation failed."
                ),
                how=(
                    "  1. When the question is pre-incident, pick preparation.\n"
                    "  2. After ignition, pick the active phase.\n"
                    "  3. Keep order straight."
                ),
                trap="calling detection 'preparation' because dashboards look ready.",
                remember="Preparation is before the ticket. Containment is during the fire.",
            ),
        ),
    ],
)

put(
    "sp_d4_12_ir_comms_docs",
    16,
    [
        (
            "Who needs to know",
            body(
                orient="IR communications and documentation keep the right people informed without leaking chaos.",
                work=(
                    "finance and legal need BEC payment-risk heads-up. Executives get status, not "
                    "raw malware samples in email. The ticket holds timeline, actions, and IOCs."
                ),
                formal="incident communications, escalation paths, and evidence documentation.",
                beats=(
                    "Comms beats:\n"
                    "  1. Need-to-know + role-based updates\n"
                    "  2. Single source of truth ticket\n"
                    "  3. Preserve evidence / chain of custody ideas\n"
                    "  4. External comms via approved spokespeople when required"
                ),
                tech=(
                    "  - Do not paste secrets into open channels\n"
                    "  - Timeline: detection time, contain time, eradicate time\n"
                    "  - Regulatory notice may be a Domain 5 overlap; know when to escalate up"
                ),
                worked=(
                    "BEC: tell finance early about payment risk. Do not wait for a perfect report."
                ),
                how=(
                    "  1. Match audience to message.\n"
                    "  2. Document actions as you go.\n"
                    "  3. Preserve evidence before cleanup when feasible."
                ),
                trap="public social posts mid-incident, or zero documentation so nobody can learn.",
                remember="Right people, clear timeline, preserved evidence.",
            ),
        ),
        (
            "Evidence",
            body(
                work="someone reimages WS-HR-03 before EDR export or memory capture when malware family is unknown.",
                formal="basic evidence handling inside IR docs.",
                beats=(
                    "Evidence beats: collect volatile/important artifacts first when safe, note who did what when, avoid altering unnecessarily."
                ),
                tech=(
                    "  - EDR timeline export into ticket\n"
                    "  - Hash samples; do not email live malware broadly"
                ),
                worked=(
                    "Reimage may be right for recovery after capture. Capture-first when analysis still matters."
                ),
                how=(
                    "  1. Balance contain vs preserve.\n"
                    "  2. Document decisions.\n"
                    "  3. Keep IOCs shareable safely (hashes/URLs)."
                ),
                trap="destroying the only evidence to 'be fast' without noting why.",
                remember="Write down what you did. Future you is a stakeholder.",
            ),
        ),
    ],
)

put(
    "sp_d4_13_sources_identity",
    17,
    [
        (
            "Build the evidence pack",
            body(
                orient="Data sources for investigations must match the question. Identity sources explain AuthN/AuthZ stories.",
                work=(
                    "spray: 4625/SigninLogs aggregates. BEC: mailbox audit + SigninLogs. Travel: "
                    "SigninLogs + HR note. Privileged add: directory audit / 4728/4720 style clues."
                ),
                formal="identity investigation sources and what each proves.",
                beats=(
                    "Identity sources:\n"
                    "  Windows Security: 4624/4625/4672/4720...\n"
                    "  Entra SigninLogs / AuditLogs\n"
                    "  Mailbox audit / UAL for rules and forwards\n"
                    "  VPN auth logs\n"
                    "  Ticket/HR context"
                ),
                tech=(
                    "  - Time bounds matter; skew clocks confuse timelines\n"
                    "  - Export rows into the ticket, do not only screenshot forever\n"
                    "  - Hunt success after failures every time"
                ),
                worked=(
                    "30 users failing from one IP → SigninLogs/SIEM identity sources. "
                    "Inbox rule → mailbox audit, not pfirewall alone."
                ),
                how=(
                    "  1. Name the activity type.\n"
                    "  2. Pick the source that records it.\n"
                    "  3. Bound time and account."
                ),
                trap="firewall PCAP as the primary source for an inbox forward question.",
                remember="Identity stories need identity sources.",
            ),
        ),
        (
            "Time bounds",
            body(
                work="you pull 'last 5 minutes' for a BEC that may have started days ago with legacy auth.",
                formal="scoping investigation windows.",
                beats=(
                    "Scope: first suspicious signal backward and forward; include rule creation time and prior successes."
                ),
                tech=(
                    "  - Retention limits may force earlier escalation for legal hold\n"
                    "  - Note UTC vs local in tickets"
                ),
                worked=(
                    "Too-narrow windows miss staging. Too-wide windows drown you. Start from IOC time and expand."
                ),
                how=(
                    "  1. Anchor on first IOC.\n"
                    "  2. Expand to related accounts/hosts.\n"
                    "  3. Document the window."
                ),
                trap="deleting logs to 'reduce noise' mid-investigation.",
                remember="Bound the window on purpose. Write it down.",
            ),
        ),
    ],
)

put(
    "sp_d4_14_sources_endpoint_net",
    17,
    [
        (
            "Endpoint pack",
            body(
                orient="Endpoint and network sources complete the investigation pack when hosts and paths matter.",
                work=(
                    "EDR process tree for excel→powershell, DNS/proxy for egress, firewall for "
                    "ALLOW/DROP, NetFlow for east-west after phishing."
                ),
                formal="endpoint and network data sources for investigations.",
                beats=(
                    "Source map:\n"
                    "  EDR/syslog process: execution chain\n"
                    "  Firewall/VPN: path open/used/blocked\n"
                    "  DNS/proxy: callback domains\n"
                    "  Email gateway: lure delivery\n"
                    "  Disk/memory forensics when deeper analysis needed"
                ),
                tech=(
                    "  - Hash + parent/child in ticket\n"
                    "  - Pair network beaconing with host who owns the socket\n"
                    "  - Do not open more RDP to investigate"
                ),
                worked=(
                    "Malware execution: EDR first. "
                    "Internet RDP exposure: firewall rules + auth attempts. "
                    "Beaconing: proxy/DNS + EDR together."
                ),
                how=(
                    "  1. Match source to artifact.\n"
                    "  2. Corroborate across planes.\n"
                    "  3. Keep containment priority."
                ),
                trap="network-only conclusions for a clear endpoint parent/child chain.",
                remember="Endpoint tells you what ran. Network tells you where it talked.",
            ),
        ),
        (
            "Network pack",
            body(
                work="ALLOW 3389 row plus no EDR on the DC means you are partly blind.",
                formal="recognizing coverage gaps as part of source selection.",
                beats=(
                    "If a source is missing, say the gap, compensate with adjacent logs, and open a coverage ticket after containment."
                ),
                tech=(
                    "  - Blind spots are Domain 4 findings too\n"
                    "  - Syslog/HEC forwarder health matters"
                ),
                worked=(
                    "No EDR on a crown jewel forces heavier network/identity reliance and faster isolation decisions."
                ),
                how=(
                    "  1. Name best source.\n"
                    "  2. Name fallback if missing.\n"
                    "  3. Document blind spots."
                ),
                trap="pretending coverage exists when the agent is missing.",
                remember="Missing telemetry is a finding. Say it out loud.",
            ),
        ),
    ],
)

put(
    "sp_d4_15_investigation_pack",
    17,
    [
        (
            "What good looks like",
            body(
                orient="An investigation pack is the evidence bundle another analyst or manager can reuse.",
                work=(
                    "ticket with What / Why / Disposition / MITRE-ish technique / IOCs / actions / "
                    "next steps. Screenshots plus exported log rows. Clear FP vs TP reason."
                ),
                formal="building a complete investigation documentation pack.",
                beats=(
                    "Pack contents:\n"
                    "  1. Summary in plain English\n"
                    "  2. Timeline\n"
                    "  3. Sources consulted\n"
                    "  4. IOCs (hashes, IPs, users, rules)\n"
                    "  5. Actions taken + who/when\n"
                    "  6. Disposition and follow-up (tune, patch, harden)"
                ),
                tech=(
                    "  - Portfolio habit matches exam/interview storytelling\n"
                    "  - Include negative findings ('no 4624 success seen')\n"
                    "  - Link CHG numbers for FP scanner cases"
                ),
                worked=(
                    "Good spray pack: source IP, user dcount, success hunt result, block action, "
                    "ticket link, detection tune note."
                ),
                how=(
                    "  1. Write so the next shift can continue.\n"
                    "  2. Separate facts from guesses.\n"
                    "  3. End with next action owners."
                ),
                trap="disposition 'looks fine' with zero evidence attached.",
                remember="If it is not in the pack, it did not happen for the next analyst.",
            ),
        ),
        (
            "Do the job",
            body(
                work="interview prompt: walk me through your last true positive.",
                formal="using the pack as a talk-track.",
                beats=(
                    "Talk-track: alert → source → contain → eradicate → recover → lessons. Point to artifacts."
                ),
                tech=(
                    "  - Keep customer data handling rules in mind for Boundry privacy\n"
                    "  - Redact secrets in exported packs when sharing broadly"
                ),
                worked=(
                    "Strong answer cites 4625 aggregates and the contain action, not vibes."
                ),
                how=(
                    "  1. Structure the story on IR phases.\n"
                    "  2. Cite sources.\n"
                    "  3. Name the control that should prevent reprise."
                ),
                trap="tool brand soup with no timeline or disposition.",
                remember="Packs win handoffs, exams, and interviews.",
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# DOMAIN 5
# ---------------------------------------------------------------------------
put(
    "sp_d5_01_governance_policy",
    17,
    [
        (
            "Policy stack",
            body(
                orient=(
                    "Governance is how leadership directs and controls security. Policies state "
                    "management intent. Standards give mandatory specifics. Procedures tell "
                    "operators how to execute."
                ),
                work=(
                    "AUP says do not bypass controls. Standard says MFA required for remote admin. "
                    "Procedure lists isolate-host steps. AUP alone does not stop Invoice.xlsm."
                ),
                formal="policy vs standard vs procedure in a working governance stack.",
                beats=(
                    "Stack:\n"
                    "  Policy → intent (AUP, information security policy)\n"
                    "  Standard → mandatory specifics (MFA for remote admin)\n"
                    "  Procedure → runnable steps (isolate, restore, offboard)\n"
                    "  Guidelines → recommended, more flexible"
                ),
                tech=(
                    "  - Effective governance shows in enforced controls, not binders\n"
                    "  - Policy bans internet RDP but ALLOW exists → governance failure\n"
                    "  - Connect policy to technical standards and practiced procedures"
                ),
                worked=(
                    "AUP is a directive policy. "
                    "Policy says no internet RDP but ALLOW exists = failure: not enforced / uncontrolled exception."
                ),
                how=(
                    "  1. Identify which document layer the question names.\n"
                    "  2. Prefer enforceability answers.\n"
                    "  3. Purpose first, product second."
                ),
                trap="picking a brand-name tool before naming the governance purpose.",
                remember="Documents mean something only when controls match written intent.",
            ),
        ),
        (
            "Effective governance",
            body(
                work="legacy auth banned in policy but still enabled in Entra.",
                formal="say/do gap as a governance finding.",
                beats=(
                    "Effectiveness checks: ownership, review cadence, enforcement evidence, exception process."
                ),
                tech=(
                    "  - Unowned policies rot\n"
                    "  - Auditors look for say/do alignment"
                ),
                worked=(
                    "Governance effectiveness shows in controls matching written intent, not pretty binders only."
                ),
                how=(
                    "  1. Compare written rule vs live config.\n"
                    "  2. Name the gap.\n"
                    "  3. Assign owner."
                ),
                trap="assuming a signed PDF equals enforcement.",
                remember="If config disagrees with policy, governance failed until fixed or excepted.",
            ),
        ),
    ],
)

put(
    "sp_d5_02_roles_exceptions",
    16,
    [
        (
            "Who decides",
            body(
                orient="Roles and responsibilities clarify who owns data, systems, approvals, and exceptions.",
                work=(
                    "everyone thought someone else disabled legacy auth. Vendor RDP was approved "
                    "in a hallway. Nobody owned the review date."
                ),
                formal="RACI-style clarity, data/system owners, and controlled exceptions.",
                beats=(
                    "Role map:\n"
                    "  Data owner / system owner / security lead / SOC / IT ops\n"
                    "  RACI prevents 'I thought you did it'\n"
                    "  Exceptions: written approval, compensating control, owner, review date"
                ),
                tech=(
                    "  - Verbal 'vendor needs it' with no expiry is how ALLOW 3389 lives forever\n"
                    "  - Security committee / CAB for high-risk changes\n"
                    "  - SOC executes; owners accept residual risk"
                ),
                worked=(
                    "Exception needs owner + compensating control + date. "
                    "Hallway yes is not an exception process."
                ),
                how=(
                    "  1. Find who owns the decision.\n"
                    "  2. Prefer documented exception answers.\n"
                    "  3. Reject infinite silent risk."
                ),
                trap="SOC 'accepting' residual risk for the business with no owner.",
                remember="Exceptions without owners are just future incidents with paperwork missing.",
            ),
        ),
        (
            "RACI in practice",
            body(
                work="who is Responsible vs Accountable for disabling legacy auth?",
                formal="using RACI vocabulary without drowning in corporate theater.",
                beats=(
                    "Accountable owns the outcome. Responsible does the work. Consulted/informed as needed."
                ),
                tech=(
                    "  - Exam may not require perfect RACI charts; it requires clear ownership\n"
                    "  - Name a human, not 'the cloud'"
                ),
                worked=(
                    "If no Accountable name exists for prod DC firewall changes, governance is broken."
                ),
                how=(
                    "  1. Look for named owners.\n"
                    "  2. Separate doer vs accepter of risk.\n"
                    "  3. Tie to exception dates."
                ),
                trap="matrix diagrams with no names.",
                remember="Clarity of ownership beats fancy charts.",
            ),
        ),
    ],
)

put(
    "sp_d5_03_risk_process",
    17,
    [
        (
            "Risk process basics",
            body(
                orient=(
                    "Risk is the combination of likelihood and impact for a threat exploiting a "
                    "vulnerability against an asset. Risk management is the process of identifying, "
                    "analyzing, and treating that risk."
                ),
                work=(
                    "open RDP to a DC is high impact. Commodity DROP noise on 445 with no path "
                    "is lower. You identify, analyze, then treat."
                ),
                formal="risk identification and analysis ahead of treatment.",
                beats=(
                    "Process beats:\n"
                    "  1. Identify assets/threats/vulns\n"
                    "  2. Analyze likelihood × impact (qualitative or quantitative)\n"
                    "  3. Evaluate against appetite/tolerance\n"
                    "  4. Treat (next lesson)\n"
                    "  5. Monitor and review"
                ),
                tech=(
                    "  - Residual risk remains after treatment\n"
                    "  - Inherent risk is before controls\n"
                    "  - Register tracks owners and statuses"
                ),
                worked=(
                    "Kill switch OFF with no owner: identify as risk, analyze impact if tunnel drops, "
                    "then treat or formally accept."
                ),
                how=(
                    "  1. Name asset + threat + weakness.\n"
                    "  2. Rough likelihood/impact.\n"
                    "  3. Do not skip to random tools before analysis."
                ),
                trap="treating all risks as equal or skipping analysis because a scanner is red.",
                remember="Risk process: identify → analyze → treat → monitor.",
            ),
        ),
        (
            "Appetite and register",
            body(
                work="leadership accepts some low risks; crown-jewel RDP exposure is outside appetite.",
                formal="risk appetite/tolerance and the risk register as governance tools.",
                beats=(
                    "Register fields that matter: risk, owner, rating, treatment, dates, residual."
                ),
                tech=(
                    "  - SOC findings should feed the register when residual risk remains\n"
                    "  - Appetite is leadership's call; analysts escalate facts"
                ),
                worked=(
                    "Analysts escalate evidence. Owners accept residual risk inside appetite."
                ),
                how=(
                    "  1. Separate analyst escalate vs owner accept.\n"
                    "  2. Prefer named register entries.\n"
                    "  3. Watch review dates."
                ),
                trap="analyst silently 'accepting' DC RDP because the queue is busy.",
                remember="Owners accept risk. Analysts surface it.",
            ),
        ),
    ],
)

put(
    "sp_d5_04_risk_treatment",
    17,
    [
        (
            "Treat the risk",
            body(
                orient=(
                    "Risk treatment choices are mitigate (reduce), accept, transfer (insurance/third party), "
                    "or avoid (stop the activity). Sometimes called risk response."
                ),
                work=(
                    "mitigate by turning kill switch ON. Accept a low lab risk with owner/date. "
                    "Transfer some cyber residual via insurance. Avoid by not offering internet RDP to DCs at all."
                ),
                formal="risk treatment options and when each fits.",
                beats=(
                    "Treatment map:\n"
                    "  Mitigate / reduce → controls that lower likelihood or impact\n"
                    "  Accept → informed, owned, documented\n"
                    "  Transfer → share residual (insurance, contract) — not a magic delete\n"
                    "  Avoid → stop doing the risky thing"
                ),
                tech=(
                    "  - Compensating controls are mitigation when preferred control is blocked\n"
                    "  - Transfer does not remove the need for basic controls\n"
                    "  - Acceptance without owner/date is denial"
                ),
                worked=(
                    "Open internet RDP to DC: avoid/mitigate (remove path), not quiet accept. "
                    "Insurance without MFA is not responsible transfer theater."
                ),
                how=(
                    "  1. Match treatment to appetite and asset.\n"
                    "  2. Demand owner/date for accept.\n"
                    "  3. Prefer path removal for crown jewels."
                ),
                trap="calling undocumented exposure 'accepted risk.'",
                remember="Treatments need owners. Acceptance is a decision, not a shrug.",
            ),
        ),
        (
            "Residual risk",
            body(
                work="after MFA and legacy auth off, some phishing residual remains; owner tracks it.",
                formal="residual risk after controls.",
                beats=(
                    "Always ask: what residual remains, who owns it, when reviewed?"
                ),
                tech=(
                    "  - Residual can be low but never mythical zero for human systems\n"
                    "  - Feed residual into awareness and detection tunes"
                ),
                worked=(
                    "Mitigation lowered likelihood; residual accepted with review date is mature. "
                    "Claiming zero risk after one control is not."
                ),
                how=(
                    "  1. Name residual.\n"
                    "  2. Name owner.\n"
                    "  3. Schedule review."
                ),
                trap="'we mitigated, so risk is zero forever.'",
                remember="Residual risk is normal. Unowned residual is not.",
            ),
        ),
    ],
)

put(
    "sp_d5_05_third_party",
    17,
    [
        (
            "Vendors are in your blast radius",
            body(
                orient="Third-party risk covers vendors, MSPs, SaaS, and supply chain partners who can hurt you.",
                work=(
                    "mail filter vendor questionnaire before buy, MSP standing admin review, "
                    "SaaS with your customer data, and a compromised updater story."
                ),
                formal="third-party risk assessment and ongoing management.",
                beats=(
                    "Third-party beats:\n"
                    "  1. Due diligence before buy (questionnaires, SOC reports, security review)\n"
                    "  2. Contracts: security clauses, breach notice, data handling\n"
                    "  3. Least privilege integration\n"
                    "  4. Continuous monitoring / access reviews\n"
                    "  5. Offboard vendors fully"
                ),
                tech=(
                    "  - Standing domain admin for MSP without review = supply-chain style risk\n"
                    "  - Shared responsibility does not vanish because SaaS is pretty\n"
                    "  - Right to audit / evidence requests vary by contract"
                ),
                worked=(
                    "Vendor questionnaire before buying a mail filter = managerial third-party review. "
                    "MSP forever-admin without review = unmanaged third-party risk."
                ),
                how=(
                    "  1. Ask what data/access the third party has.\n"
                    "  2. Prefer least privilege + review answers.\n"
                    "  3. Include offboarding."
                ),
                trap="trusting logos instead of access reviews.",
                remember="Third parties inherit your blast radius. Review them like it.",
            ),
        ),
        (
            "Ongoing management",
            body(
                work="SaaS app still has ten unused admin accounts from a pilot last year.",
                formal="continuous third-party access hygiene.",
                beats=(
                    "Ongoing: inventory integrations, review admins, monitor alerts, renew diligence on tier-1 vendors."
                ),
                tech=(
                    "  - Tier vendors by data sensitivity / access depth\n"
                    "  - Incident clauses matter when their breach becomes your incident"
                ),
                worked=(
                    "Pilot leftovers are third-party lifecycle failures."
                ),
                how=(
                    "  1. Tier the vendor.\n"
                    "  2. Review access.\n"
                    "  3. Keep contract obligations in view."
                ),
                trap="one-time questionnaire forever.",
                remember="Third-party risk is a loop, not a purchase checkbox.",
            ),
        ),
    ],
)

put(
    "sp_d5_06_compliance",
    16,
    [
        (
            "Compliance vs security",
            body(
                orient=(
                    "Compliance means meeting required rules (laws, regulations, contracts, "
                    "internal policies). Security is the actual protection. You want both. "
                    "Compliance alone can be checkbox theater."
                ),
                work=(
                    "a PCI or privacy obligation forces encryption and access logging. Passing "
                    "an audit last year does not mean open RDP is fine today."
                ),
                formal="compliance requirements as drivers, not substitutes, for security controls.",
                beats=(
                    "Compliance beats:\n"
                    "  1. Know applicable obligations at a high level\n"
                    "  2. Map controls to requirements\n"
                    "  3. Evidence continuously, not only at audit week\n"
                    "  4. Fix say/do gaps"
                ),
                tech=(
                    "  - Logging/retention may be compliance-driven and investigation-helpful\n"
                    "  - Contractual customer requirements can bind Boundry client work\n"
                    "  - Privacy rules affect how you handle evidence packs"
                ),
                worked=(
                    "Encrypted backups may satisfy a requirement and still fail ransomware if online-only. "
                    "Meet the letter and the risk."
                ),
                how=(
                    "  1. Separate 'required by rule' from 'enough to be safe.'\n"
                    "  2. Prefer continuous evidence.\n"
                    "  3. Fix real exposure even if last audit passed."
                ),
                trap="checkbox compliance while crown-jewel paths stay open.",
                remember="Compliance is necessary. It is not automatic security.",
            ),
        ),
        (
            "Evidence habit",
            body(
                work="audit asks for MFA proof; you scramble screenshots from one laptop.",
                formal="continuous control evidence.",
                beats=(
                    "Evidence habit: export configs, ticket trails, access reviews, training completion on a cadence."
                ),
                tech=(
                    "  - SIEM/ticket history helps prove detective/response controls\n"
                    "  - Change tickets prove governance of exceptions"
                ),
                worked=(
                    "Teams that evidence monthly do not panic yearly."
                ),
                how=(
                    "  1. Prefer ongoing evidence answers.\n"
                    "  2. Tie controls to owners.\n"
                    "  3. Keep exports retrievable."
                ),
                trap="evidence that exists only in one person's head.",
                remember="If you cannot show it, auditors assume it does not exist.",
            ),
        ),
    ],
)

put(
    "sp_d5_07_audits_assessments",
    16,
    [
        (
            "Audits and assessments",
            body(
                orient=(
                    "An audit checks against criteria and produces findings. An assessment "
                    "evaluates posture more broadly. Internal vs external changes independence."
                ),
                work=(
                    "internal audit samples firewall exceptions. External assessor reviews "
                    "identity controls. Findings get owners and due dates."
                ),
                formal="audits vs assessments and finding remediation.",
                beats=(
                    "Map:\n"
                    "  Internal audit → independence inside org varies by design\n"
                    "  External audit/assessment → outside party\n"
                    "  Finding → gap vs criteria\n"
                    "  Remediation → fix + evidence + retest"
                ),
                tech=(
                    "  - SOC 2-style reports are vendor assurance inputs, not blind trust cards\n"
                    "  - Penetration tests and vuln scans are assessment types (next lesson contrast)"
                ),
                worked=(
                    "Finding: legacy auth enabled against policy. Remediation: disable + evidence SigninLogs + owner sign-off."
                ),
                how=(
                    "  1. Identify audit vs assessment intent.\n"
                    "  2. Prefer owned remediation.\n"
                    "  3. Ask for evidence of closure."
                ),
                trap="shelving findings until the next audit cycle without risk treatment.",
                remember="Findings need owners and due dates, not binders.",
            ),
        ),
        (
            "Independence and scope",
            body(
                work="the team that built the firewall also 'audits' itself with no outside review.",
                formal="independence and scope clarity.",
                beats=(
                    "Good practice: clear scope, criteria, independence appropriate to the claim."
                ),
                tech=(
                    "  - Self-assessment is useful but not the same as independent audit\n"
                    "  - Scope games hide crown jewels"
                ),
                worked=(
                    "If DC RDP was scoped out every year, the clean report is marketing."
                ),
                how=(
                    "  1. Check scope.\n"
                    "  2. Check independence claims.\n"
                    "  3. Follow findings to closure."
                ),
                trap="trusting a clean report with suspicious scope exclusions.",
                remember="Scope and independence decide how much a report means.",
            ),
        ),
    ],
)

