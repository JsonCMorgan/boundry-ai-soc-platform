"""D4 lesson specs for Phase 1 generator. Security Operations (heaviest).

Voice: .cursor/rules/tutor-professor-voice.mdc (define before use).
Depth: Option 1 ~15-20 min Show-me; work-facing picture + technical specifics.
SY0-801 deeper drills live in gen_secplus_d4_801.py.
"""
from __future__ import annotations

from gen_secplus_d4_801 import (
    register_d4_801_agentic_guardrails,
    register_d4_801_bimi_email_auth,
    register_d4_801_cspm_bug_bounty,
    register_d4_801_honeyfile_deception,
    register_d4_801_passkeys_jit,
)


def d4_specs(add, _mc, _qz):
    """Register Domain 4 micro-lessons (20 including SY0-801 deeper drills)."""

    add(
        "sp_d4_01_harden_compute", "d4_operations", "4.1",
        "Hardening computing resources", 18,
        ["Hardening", "Secure Baseline", "Least Privilege", "Disk Encryption", "EDR", "XDR"],
        [
            ("What you touch on a ticket", """
                Hardening means reducing attack surface on compute: operating systems, virtual machines, containers, and golden images. Attack surface is every service, account, and tool an attacker could abuse.

                Where you see this at work: you remove local admin from HR laptops, enable EDR and ASR (attack surface reduction) rules, patch, disable unused services, turn on PowerShell script block logging on jump hosts, and confirm BitLocker on traveling devices.

                In Security+ terms, that is compute hardening techniques used in day-to-day ops.

                Compute harden list:
                  1. Patch / update on a measured cadence
                  2. Remove unused roles, services, and listeners
                  3. Least privilege: no standing local admin for daily work
                  4. EDR healthy + ASR / application control where used
                  5. Secure baseline (CIS-style or org GPO/Intune) + disk encryption
                  6. Host firewall on; unnecessary ports closed

                Technical specifics:
                - ASR example: block Office apps from creating child processes (excel.exe → powershell.exe -enc is the classic fail)
                  - Jump / PAM hosts: no email, no browsing, MFA, stricter audit (4688 process create / PowerShell 4104 where enabled)
                  - Containers: minimal base image, non-root, scanned in CI, no secrets baked into layers
                  - Verify after deploy: test that Office→script is blocked on a canary host
                  - Drift: golden image Monday, HR laptop Friday with local admin again = hardening failed
                  - Disk encryption (BitLocker/FileVault) protects lost devices; it does not stop a logged-in macro

                Worked example:
                Invoice.xlsm opens on WS-HR-03. Macros launch powershell.exe -enc. EDR alerts. Which harden controls should already have been in place?
                  - Prefer: ASR / macro block + least local admin + healthy EDR
                  - Not enough alone: wallpaper policy, annual AUP click, prettier SIEM theme
                  - After the fact: isolate (corrective). That is IR, not proof you hardened.

                                More desk clues:
                  - Verify ASR actually blocks Office→script on a test host after deploy.
                  - Jump hosts: stricter logging, no email browsing, MFA, limited tools.
                  - Containers: minimal base image, non-root, scanned, secrets not baked in.
                  - If excel→powershell still works, the harden ticket is not done.

                How to answer on the exam:
                1. Name the compute surface (laptop, jump host, container, VM).
                  2. Pick the harden control that closes the path in the question.
                  3. Prefer prevent (ASR, remove admin, patch) before detect-only answers.
                  4. Ask whether the control was verified after deploy.

                Common trap: answering 'install more wallpaper' or 'disable EDR to speed the PC.' Another near-miss: calling BitLocker the fix for Office→script on an unlocked session. BitLocker is at-rest. The path was execution.

                801 desk note: healthy EDR is preventive/detective on the host; XDR correlates
                that host with identity/email/network. Isolation after execution is still
                corrective response, not proof you hardened beforehand.

                Remember: Hardening removes paths before the alert fires. Verify it still holds after drift.
                """),
            ("Do the job", """
                Where you see this at work: PBQ-style match: each failure maps to one harden move you can name.

                In Security+ terms, that is applying hardening that matches the scenario.

                Quick fits:
                  Macro→PS → ASR / block internet macros
                  Standing local admin → remove / PAM
                  Unpatched VPN client → patch or replace
                  Cleartext laptop at rest → BitLocker
                  Secrets in container image → rebuild + secret store

                Technical specifics:
                - Change-control hardening pushes (CHG). Verify after deploy.
                  - Exceptions need owner + compensating control + review date
                  - Baseline tools: Intune/GPO/Ansible/image pipelines, not tribal memory

                Worked example:
                If excel→powershell still works after a 'hardening' ticket, you hardened the wrong control or never verified. Reopen the ticket. Do not mark done.

                How to answer on the exam:
                1. Match control to path.
                  2. Verify the control actually applied.
                  3. Keep exceptions owned.

                Common trap: claiming hardened when the original execution path still works on a test host.

                Remember: Verify hardening. Drift undoes baselines.
                """),
        ],
        [
            _mc("Best hardening move against Office→script?",
                ["Open more macros", "ASR / block Office child processes + reduce local admin",
                 "Disable EDR", "Ignore"], 1,
                "Stop the launch.",
                "Correct. Hardening is preventive ops work. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Disk encryption on laptops is an ops technique to:",
                ["Speed spray", "Protect data if devices are lost",
                 "Replace SIEM", "Open RDP"], 1,
                "At-rest control on the fleet."),
            _mc("Standing local admin on every workstation breaks:",
                ["Least privilege hardening", "Only toner alerts", "Only RPO text", "DNS"], 0,
                "Privilege sprawl."),
        ],
        [
            _qz("q_d4_01a", "Secure baseline purpose in ops:",
                ["Consistent hardened config you can audit", "Random configs",
                 "Open 3389", "Delete logs"], 0,
                "Correct. Fleet consistency. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_01b", "Patching endpoints is:",
                ["4.1-style hardening / maintenance", "Only Domain 5 posters",
                 "Only physical", "Only honeypots"], 0,
                "Correct. Reduce vulns in ops. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_01c", "Disabling unused RDP on servers is:",
                ["Surface reduction hardening", "Required internet expose",
                 "Awareness only", "RTO"], 0,
                "Correct. Turn off what you do not need. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_01d", "After finding svc_backup2, hardening follow-up includes:",
                ["Ignore accounts", "Review local admin membership and monitoring",
                 "Open more ports", "Disable MFA"], 1,
                "Correct. Privilege audit. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    pbq_harden = {
        "id": "pbq_d4_harden",
        "kind": "pick",
        "title": "Pick the hardening package",
        "prompt": (
            "Third Invoice.xlsm → powershell -enc this quarter on HR. What ops hardening "
            "package do you push (not only IR for this host)?"
        ),
        "choices": [
            {"id": "pkg", "text": "ASR Office→script, mail macro policy, local admin reduction, EDR mode enforce"},
            {"id": "poster", "text": "Only a new poster; leave macros and local admin"},
            {"id": "rdp", "text": "Expose HR RDP to internet for faster reimaging"},
            {"id": "off", "text": "Turn off EDR to reduce alerts"},
        ],
        "answer": "pkg",
        "explain": (
            "Correct. Ops hardening closes the class of incident. Posters alone fail. Common trap:"
            "near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_02_harden_network_app", "d4_operations", "4.1",
        "Hardening network and application paths", 17,
        ["Port Security", "Secure Protocols", "Application Allow Listing", "TLS"],
        [
            ("Close management paths", """
                Network and application hardening closes remote-access and app-layer paths. Management plane means admin protocols (RDP, SSH, vendor consoles).

                Where you see this at work: deny inbound TCP 3389 and TCP 22 from the internet, require MFA VPN or a jump host, turn off unused HTTP verbs and sample pages, put TLS on admin UIs, and rate-limit login endpoints that get sprayed.

                In Security+ terms, that is network and application hardening in operations.

                Network/app harden:
                  1. Management plane not on the open internet
                  2. TLS on apps; no cleartext admin
                  3. Remove default accounts, passwords, and sample pages
                  4. Patch apps; input validation / secure headers where you own code
                  5. API keys not in mobile apps, chat, or repos

                Technical specifics:
                - Priority path: internet → TCP 3389/22 → domain controller or jump host beats most CVE chatter until that ALLOW is gone
                  - Brokered admin: VPN (UDP 500/4500 or TLS VPN) + PAM/jump + MFA
                  - WAF helps HTTP classes (injection, some bot abuse). It does not close non-HTTP management ports
                  - Disable legacy app auth that bypasses MFA (basic auth, legacy SMTP/POP)
                  - After removing 3389 ALLOW: confirm with rule review + external scan + SIEM quiet on that path

                Worked example:
                Firewall shows ALLOW tcp/3389 from 0.0.0.0/0 to PROD-DC01. App team wants a WAF purchase for a different web app the same week.
                  - First harden: remove or broker that RDP path (network harden)
                  - WAF may help the web app later; it is the wrong primary answer for RDP
                  - Default /admin with vendor password on a public site is app hardening

                                More desk clues:
                  - Management plane exposure beats app CVE arguments when 3389/22 face the internet.
                  - App defaults: remove /admin vendor passwords, unused verbs, sample pages.
                  - Put TLS on admin UIs. Rate-limit login endpoints that get sprayed.
                  - WAF helps HTTP classes. It does not close non-HTTP management ports.

                How to answer on the exam:
                1. Find the exposed service and protocol.
                  2. Close or broker access before shopping new dashboards.
                  3. Patch and remove defaults on what must stay exposed.

                Common trap: WAF-only answer for a non-HTTP management port exposure. Another near-miss: 'we have SIEM' as a substitute for closing internet RDP.

                Remember: Close management paths first. Then harden the app features you must expose.
                """),
            ("App layer", """
                Where you see this at work: a public form reflects script tags; another app still has /admin with the vendor default password; a repo has cloud keys in plaintext.

                In Security+ terms, that is application security hygiene as ops hardening.

                App beats: patch, remove defaults, least-privilege DB accounts, secrets management, rate-limit auth endpoints.

                Technical specifics:
                - Secrets in Git are an ops finding with rotate + purge history as needed
                  - Rate limiting and lockout help password spray against login pages
                  - TLS on the admin UI; HSTS where appropriate
                  - Remove sample apps and debug endpoints from prod

                Worked example:
                Default creds on a public admin page are Domain 2 (exposure) and Domain 4 (failed harden). Fix: remove defaults, force unique secrets, put admin off the open internet if possible.

                How to answer on the exam:
                1. Remove defaults.
                  2. Patch.
                  3. Protect secrets and auth endpoints.

                Common trap: calling secure coding optional because a SIEM exists.

                Remember: Exposed apps need harden + monitor, not monitor alone.
                """),
        ],
        [
            _mc("Ops technique for exposed RDP finding?",
                ["Leave ALLOW; add wallpaper", "Change request to remove; VPN/PAM path",
                 "Disable logging", "Shame the firewall"], 1,
                "Close the port.",
                "Correct. Hardening includes network exposure removal. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Preferring HTTPS/SSH over cleartext is:",
                ["Secure protocol hardening", "Only physical", "Only RPO", "SOAR disable"], 0,
                "Crypto in transit as ops standard."),
            _mc("Application allow-listing purpose?",
                ["Run everything", "Only approved binaries run: hard for commodity malware",
                 "Open 3389", "Delete SIEM"], 1,
                "High friction, high value on sensitive hosts."),
        ],
        [
            _qz("q_d4_02a", "Legacy auth disable is ops hardening for:",
                ["Identity protocols", "Only printers", "Only cages", "Only RTO"], 0,
                "Correct. Close weak auth. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_02b", "TLS 1.0 still on a payment portal is:",
                ["Fine forever", "Protocol hardening debt", "A honeypot success", "CHG noise only"], 1,
                "Correct. Deprecate weak crypto. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_02c", "Admin via jump host + MFA is:",
                ["Hardened remote admin pattern", "Worse than internet RDP to DC",
                 "Only Domain 1 vocab", "Physical only"], 0,
                "Correct. Controlled path. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_02d", "After removing 3389 ALLOW you should:",
                ["Never verify", "Verify with scan/firewall config + monitor for new ALLOWs",
                 "Open 445 instead", "Disable EDR"], 1,
                "Correct. Verify the change. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        pbq_harden,
        job_ctas="d4",
    )

    # 801 deeper drills for 4.1 email-auth / deception (after baseline harden lessons).
    register_d4_801_bimi_email_auth(add, _mc, _qz)
    register_d4_801_honeyfile_deception(add, _mc, _qz)

    add(
        "sp_d4_03_asset_management", "d4_operations", "4.2",
        "Asset management that prevents ghost admins", 18,
        ["Asset Inventory", "Ownership", "Classification", "Lifecycle"],
        [
            ("Why svc_backup2 at 03:14 is a crisis", """
                Asset management means knowing what you have, who owns it, how sensitive it is, and what privilege it holds. You cannot defend ghosts.

                Where you see this at work: a new local admin svc_backup2 appears at 03:14 with no change ticket. Inventory did not list that service account as approved. VPN objects and SaaS admins were never in the CMDB either.

                In Security+ terms, that is hardware, software, data, and account asset management with lifecycle hygiene.

                Asset beats:
                  1. Inventory devices, apps, accounts, data stores, cloud roles
                  2. Owner and classification for each critical asset
                  3. Lifecycle: joiner / mover / leaver / decommission
                  4. Remove ghost admins, stale VPN, orphaned API keys

                Technical specifics:
                - Unexpected privileged account = integrity + asset control failure; hunt 4720/4728-style creates and local admin group changes
                  - Inventory must include service accounts, break-glass, VPN profiles, and SaaS OAuth apps, not only laptops
                  - Offboard day-0 checklist: disable account, revoke MFA devices, pull groups, wipe/return device, kill tokens
                  - Shadow IT appears where ownership and inventory are weak
                  - Classification (public / internal / confidential) drives backup, DLP, and who may admin

                Worked example:
                svc_backup2 at 03:14, no CHG, missing from inventory:
                  - Escalate as unauthorized privilege, not 'backups need admin'
                  - Contain: disable/reset, isolate if host-tied, hunt lateral use
                  - Program fix: inventory + joiner/mover/leaver SLA so ghosts cannot hide

                                More desk clues:
                  - Inventory must include service accounts and VPN objects, not only laptops.
                  - Offboard day-0: disable account, revoke MFA devices, pull groups, wipe/return device.
                  - Unknown privileged account at 03:14 is asset + integrity + IR in one alert.
                  - Shadow IT appears where inventory and ownership are weak.

                How to answer on the exam:
                1. Ask if the asset or account should exist.
                  2. Check owner and ticket.
                  3. Prefer lifecycle answers for stale access.

                Common trap: ignoring unknown admins because 'backups need admin.' Near-miss: only counting laptops while privileged SaaS and VPN objects stay invisible.

                Remember: You cannot defend assets you do not know you have.
                """),
            ("Lifecycle", """
                Where you see this at work: contractor laptop and VPN still active 60 days after offboarding.

                In Security+ terms, that is asset and identity lifecycle operations.

                Offboard checklist: account disable, MFA devices, VPN, groups, laptop return/wipe, API tokens, shared mailbox access.

                Technical specifics:
                - Orphaned privileged service accounts are crown-jewel debt
                  - CMDB / Intune / Entra accuracy is a control input, not paperwork vanity
                  - Mover events (new role) need group changes the same week, not 'someday'

                Worked example:
                Stale contractor VPN is an asset/identity lifecycle miss and a remote vector. Treat it like an open path: revoke, then find how long it stayed open.

                How to answer on the exam:
                1. Look for joiners/movers/leavers clues.
                  2. Pick revoke/decommission answers.
                  3. Tie ownership to inventory.

                Common trap: keeping access 'just in case' with no owner or review date.

                Remember: Lifecycle failures become Domain 2 vectors.
                """),
        ],
        [
            _mc("Unknown local admin overnight is partly an asset/IAM failure because:",
                ["Inventory/ownership of privileged identities was weak", "Printers hate SIEM",
                 "RTO is zero", "Hashing failed"], 0,
                "Know your privileged assets.",
                "Correct. You cannot defend what you do not inventory. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Stale vendor VPN with no owner is:",
                ["Lifecycle failure", "Perfect ZT", "Only Domain 1", "A honeypot"], 0,
                "Deprovision missing."),
            _mc("Classifying PROD-DC01 as crown jewel drives:",
                ["Ignoring its logs", "Higher monitoring / stricter change control",
                 "Opening more RDP", "Deleting backups"], 1,
                "Tiering."),
        ],
        [
            _qz("q_d4_03a", "Asset inventory should include:",
                ["Only mice", "Hosts, apps, data stores, identities, cloud objects",
                 "Only posters", "Only toner"], 1,
                "Correct. Broad inventory. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_03b", "Owner field purpose:",
                ["Blame games only", "Who approves changes and responds to findings",
                 "Open ports", "Disable MFA"], 1,
                "Correct. Accountability. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_03c", "Deprovisioning leftover accounts prevents:",
                ["All phishing", "Standing access abuse", "Need for TLS", "Need for tickets"], 1,
                "Correct. Kill stale paths. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_03d", "Data asset classification helps ops by:",
                ["Prioritizing DLP and response", "Removing encryption need",
                 "Replacing IR", "Forcing RDP"], 0,
                "Correct. Focus controls. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    pbq_vuln = {
        "id": "pbq_d4_vuln",
        "kind": "pick",
        "title": "Scanner vs exposure",
        "prompt": (
            "Nessus from approved scanner IP with ticket SEC-220 vs ALLOW 3389 from "
            "203.0.113.88 to PROD-DC01. Difference?"
        ),
        "choices": [
            {"id": "ctx", "text": "Authorized vuln activity vs likely exposure/incident: context and identity decide"},
            {"id": "same", "text": "They are identical CRITICAL incidents"},
            {"id": "info", "text": "Both are INFO because ports are just numbers"},
            {"id": "ransom", "text": "Nessus means the DC is already ransomware'd"},
        ],
        "answer": "ctx",
        "explain": (
            "Correct. Vuln management and IR share ports; they do not share disposition. Common trap:"
            "near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_04_vuln_lifecycle", "d4_operations", "4.3",
        "Vulnerability management lifecycle", 18,
        ["Vulnerability Scan", "Risk Score", "Remediation", "Exception"],
        [
            ("Scan is not done", """
                Vulnerability management is a lifecycle: discover, prioritize, remediate, verify, then exception if needed. A scan file alone is not management.

                Where you see this at work: Nessus finishes, tickets open with owners, teams patch or accept risk with a date, then rescans prove closure. A medium CVE on PROD-DC01 can outrank a critical on a lab printer.

                In Security+ terms, that is vulnerability management lifecycle operations.

                Lifecycle:
                  1. Discover (scan / agent / inventory / threat intel)
                  2. Prioritize (severity + asset value + exploitability + path open)
                  3. Remediate (patch / config fix / compensate)
                  4. Verify (rescan or config proof)
                  5. Exception with owner, compensating control, and review if needed

                Technical specifics:
                - CVSS is an input, not a religion. Asset context can override color
                  - Misconfigs without a CVE (open 3389, legacy auth) still enter the same loop
                  - SLA examples teams use: critical internet-facing days, not months
                  - Rescan is the verify step. Green ticket without rescan is incomplete
                  - Exceptions need compensating control + owner + review date + approver
                  - KEV / active exploit intel can jump a medium ahead of a quiet critical

                Worked example:
                Scan drops 200 findings. Analyst files zero tickets. Manager asks 'are we done?'
                  - No. Discover without prioritize/remediate/verify is incomplete
                  - Prioritize: DC + internet path first; lab printer later
                  - Exception without expiry for internet RDP to DC is a governance failure, not mature risk acceptance

                                More desk clues:
                  - Prioritize with asset value: medium CVE on a DC can outrank critical on a lab printer.
                  - Misconfig without CVE still enters discover→remediate→verify.
                  - Exceptions need compensating control + owner + review date.
                  - Rescan is the verify step. Green tickets without rescan are incomplete.

                How to answer on the exam:
                1. Do not stop at 'scanned.'
                  2. Prioritize by risk, not only by color.
                  3. Verify closure with rescan or equivalent proof.

                Common trap: closing criticals as 'accepted' with no owner, compensating control, or date. Near-miss: treating CVSS 9 on an offline lab higher than CVSS 6 on a DC with an open management path.

                Remember: Vulnerability management ends at verified fix or owned exception.
                """),
            ("Exceptions", """
                Where you see this at work: legacy OT box cannot patch; you segment and monitor with a 90-day review.

                In Security+ terms, that is owned compensating exceptions inside vulnerability management.

                Exception needs: reason, compensating control, owner, review date, approver.

                Technical specifics:
                - Internet RDP to a DC should almost never clear exception review
                  - Prefer architecture fix (segment, broker) over eternal paperwork
                  - Tie exception IDs into SIEM suppressions so tuning stays honest

                Worked example:
                Documented segment + monitor for unpatchable OT can be valid. Hallway yes for DC RDP is not. Write the compensating control or remove the path.

                How to answer on the exam:
                1. Prefer remediate.
                  2. If except, demand compensating control + date.
                  3. Reject silent risk.

                Common trap: treating exceptions as permanent wallpaper.

                Remember: Exceptions expire or they become culture.
                """),
        ],
        [
            _mc("Nessus SEC-220 from approved scanner vs hostile 3389 ALLOW. Difference?",
                ["Identical CRITICAL", "Authorized vuln activity vs exposure/incident: context decides",
                 "Both INFO", "Nessus = ransomware"], 1,
                "Who scanned, approval, asset tier.",
                "Correct. Disposition differs. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Vulnerability management ends at the scan report?",
                ["Yes", "No: remediate/verify or exception with owner",
                 "Yes if PDF is pretty", "Only if RDP open"], 1,
                "Lifecycle."),
            _mc("Prioritize patch on internet-facing DC vuln over offline printer CVE because:",
                ["Printers are sacred", "Asset exposure and blast radius",
                 "Fonts", "Only Domain 5"], 1,
                "Risk = likelihood × impact."),
        ],
        [
            _qz("q_d4_04a", "Verify step in vuln mgmt means:",
                ["Rescan / confirm fixed", "Delete the finding always",
                 "Open more ports", "Disable SIEM"], 0,
                "Correct. Prove closure. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_04b", "Risk-based prioritization uses:",
                ["Only CVE date", "Asset criticality + exploitability + exposure",
                 "Only analyst mood", "Only toner"], 1,
                "Correct. Context. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_04c", "Exception without review date is:",
                ["Strong governance", "Drift waiting to become an incident",
                 "Required ZT", "A honeypot"], 1,
                "Correct. Time-box risk. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_04d", "IDS alert on JUMP-01 with CHG-512 likely:",
                ["Nation-state", "Authorized scan FP if identity matches",
                 "Proof to open 3389", "BEC"], 1,
                "Correct. Context. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        pbq_vuln,
        job_ctas="d4",
    )

    add(
        "sp_d4_05_vuln_scan_context", "d4_operations", "4.3",
        "Scan windows, agents, and validation", 17,
        ["Credentialed Scan", "Agent", "Scan Window", "False Positive"],
        [
            ("Better findings", """
                Scan context means knowing what you scanned, with what credentials, under which change ticket, and whether the target can tolerate the scan.

                Where you see this at work: JUMP-01 runs an authenticated Nessus scan under CHG-512. Separately, internet noise hits the edge. Separately, someone almost scanned OT at noon with aggressive plugins.

                In Security+ terms, that is vulnerability scanning with authorization, scope, and safety.

                Context beats:
                  1. Authorized scope + window (CHG)
                  2. Credentialed vs uncredentialed tradeoffs
                  3. Asset criticality in prioritization
                  4. Safe methods for fragile / OT systems

                Technical specifics:
                - Credentialed scans find missing patches and local issues better; protect scanner credentials like tier-0 secrets
                  - Match scanner host/IP in SIEM to CHG before paging APT on JUMP-01
                  - Allow-list the scanner in firewall/SIEM exceptions in the same ticket
                  - OT/ICS: vendor-approved or passive methods, stop conditions, off-peak
                  - Uncredentialed edge scans still help find exposure; they are not a full inventory

                Worked example:
                SIEM fires on JUMP-01 port sweeps. Ticket shows CHG-512 authenticated scan:
                  - Document as authorized activity; do not open a nation-state novel
                  - Contrast: same ports from an unknown overseas IP with no CHG → investigate
                  - Aggressive OT scan at noon without approval → stop, safety + change miss

                                More desk clues:
                  - Match scanner host/IP to CHG before paging APT on JUMP-01.
                  - Credentialed scans need protected scanner credentials and least privilege.
                  - Fragile OT: approved methods, windows, stop conditions.
                  - Allow-list the scanner in the same ticket as the firewall/SIEM exception.

                How to answer on the exam:
                1. Check authorization and scope.
                  2. Use asset context in priority.
                  3. Do not confuse scanner traffic with attackers without identity checks.

                Common trap: escalating known scanner IPs with matching CHG as APT. Near-miss: skipping credentialed scans forever because uncredentialed PDFs look green.

                Remember: Scanner context saves shifts. Safety protects fragile systems.
                """),
            ("Safety", """
                Where you see this at work: someone runs a full aggressive scan against the plant network at noon.

                In Security+ terms, that is safe scanning practices.

                Safety: approve scope, rate limits, avoid peak on fragile hosts, stop on adverse impact, document scanner allow-lists with the ticket.

                Technical specifics:
                - Production DC scans may still need change windows when disruptive
                  - Record plugin sets and exclusions so results are repeatable
                  - Adverse impact without a stop plan fails safety and change management

                Worked example:
                Plant scan knocks a PLC offline. No CHG, no stop plan. That is an ops miss even if the intent was 'security.'

                How to answer on the exam:
                1. Look for approval and safety cues.
                  2. Prefer controlled scanning answers.
                  3. Keep CHG linkage.

                Common trap: unscoped scanning because 'security said so.'

                Remember: Authorized and safe beats loud and reckless.
                """),
        ],
        [
            _mc("Why schedule vuln scans in CHG?",
                ["To confuse SIEM forever", "So SOC can treat matching traffic as authorized",
                 "To open RDP", "To disable MFA"], 1,
                "Reduce FP pain."),
            _mc("Credentialed scan advantage?",
                ["Hides all vulns", "Deeper visibility into missing patches/configs",
                 "Replaces backups", "Deletes logs"], 1,
                "Auth'd view."),
            _mc("Exploiting prod without approval to 'confirm CVE' is:",
                ["Best practice", "Unauthorized and likely an incident you caused",
                 "Required by Sec+", "Only Domain 1"], 1,
                "Stay in scope."),
        ],
        [
            _qz("q_d4_05a", "Agent-based inventory helps vuln mgmt by:",
                ["Knowing what is actually installed", "Opening 3389",
                 "Disabling EDR", "Skipping owners"], 0,
                "Correct. Coverage. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_05b", "FP in vuln scanning means:",
                ["Finding is wrong/not applicable", "Always ignore CRITICAL",
                 "Ransomware confirmed", "Open RDP"], 0,
                "Correct. Validate. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_05c", "Internet-edge vuln vs isolated lab vuln:",
                ["Same urgency always", "Edge usually higher priority due to exposure",
                 "Lab always higher", "Never patch either"], 1,
                "Correct. Exposure. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_05d", "Scan window documentation belongs in:",
                ["Change / vuln process records", "Attacker notes only",
                 "Nowhere", "Only Slack memes"], 0,
                "Correct. Ops memory. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    # 801 deeper drill for 4.3 CSPM / bounty (after baseline vuln lessons).
    register_d4_801_cspm_bug_bounty(add, _mc, _qz)

    add(
        "sp_d4_06_alerting_queue", "d4_operations", "4.4",
        "Alerting, monitoring, and the queue", 18,
        ["SIEM", "Alert Triage", "False Positive", "True Positive", "Use Case"],
        [
            ("Single pane vs right pane", """
                Alerting and monitoring means collecting signals and working a queue. A single pane of glass is one console view. The right pane is the source that actually explains the alert.

                Where you see this at work: SIEM fires Failed Logon Burst. You do not stare at a pretty dashboard. You open SigninLogs or Windows 4625, check for 4624 success, check CHG, then contain or mark false positive with notes.

                In Security+ terms, that is alert triage workflow: prioritize, validate, escalate, document.

                Queue beats:
                  1. Prioritize by severity + asset tier + path open + execution already?
                  2. Validate true positive vs false positive / CHG
                  3. Contain when needed
                  4. Ticket with evidence
                  5. Tune noisy rules with change control

                Technical specifics:
                - Alert is not an incident until validated
                  - Priority inputs: CRITICAL/HIGH labels, crown-jewel asset, open ALLOW, EDR prevention failed
                  - Live malware or BEC: contain before writing the novel
                  - Correlation thresholds must match reality (scanner nights vs spray)
                  - SOAR can enrich WHOIS, geo, ticket fields; humans gate destructive actions
                  - Disposition language: TP / FP / benign-true (authorized scan) with CHG link

                Worked example:
                Two alerts in one hour:
                  A) 30 distinct users failing from one IP, then one 4624 success
                  B) JUMP-01 sweeps matching CHG-512
                Treat A as likely spray: block/rate-limit, hunt success, ticket. Treat B as authorized: document FP/benign with CHG. Same queue, different urgency.

                                More desk clues:
                  - Priority inputs: severity, asset tier, whether a path is open, whether execution already happened.
                  - Validate with the right source in minutes, not with dashboard vibes.
                  - Live malware/BEC: contain before writing the novel.
                  - Tune noise with CHG-linked exceptions. Do not disable crown-jewel detections.

                How to answer on the exam:
                1. Read severity and asset.
                  2. Validate with the right source in minutes.
                  3. Act, then document.

                Common trap: closing high-severity crown-jewel path alerts as noise because the queue is long. Near-miss: identical handling for CHG scanners and real spray.

                Remember: Work the queue by path and asset, not by who yelled last.
                """),
            ("Boundry habit", """
                Where you see this at work: alert → source → contain → ticket, in that order when execution or BEC is live.

                In Security+ terms, that is SOC operating rhythm for Domain 4.

                Habit: do not write a novel before containment when malware is running.

                Technical specifics:
                - Enrichment first is fine if it is seconds, not hours
                  - Document enough for the next analyst: sources, IOCs, actions, disposition
                  - Tune noise with CHG-linked exclusions; do not disable crown-jewel detections

                Worked example:
                Encoded PowerShell alert on finance laptop: isolate first, then hunt the campaign hash in mail and EDR. Essay after containment.

                How to answer on the exam:
                1. Live threat → contain first.
                  2. Ambiguous → validate fast.
                  3. Always leave a ticket trail.

                Common trap: analysis paralysis while the host encrypts shares.

                Remember: Alert to source to contain to ticket.
                """),
        ],
        [
            _mc("Suspected Entra password spray: first data source?",
                ["pfirewall 445 DROPs only", "SigninLogs / 4625 with time bound + failures by IP/user",
                 "Printer SNMP", "CEO calendar colour"], 1,
                "Identity logs.",
                "Correct. Identity attacks need identity logs. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Forever-FP scanner use case: best ops move?",
                ["Disable SIEM", "Tune allow-list / exception with CHG context",
                 "Open RDP", "Ignore CRITICAL forever"], 1,
                "Tune, don't blind yourself."),
            _mc("True positive means:",
                ["Alert was wrong", "Alert correctly indicated bad/suspicious activity",
                 "Only CHG", "Only toner"], 1,
                "TP vs FP."),
        ],
        [
            _qz("q_d4_06a", "Alert triage considers:",
                ["Only font size", "Severity, asset, context, correlated evidence",
                 "Only day of week", "Only RPO"], 1,
                "Correct. Analyst judgment. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_06b", "Use case tuning purpose:",
                ["Increase noise forever", "Improve signal quality",
                 "Delete all TP", "Open 3389"], 1,
                "Correct. Signal. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_06c", "EDR alert excel→powershell: open which pane first?",
                ["Only pfirewall 445", "EDR process tree / endpoint timeline",
                 "Only AUP PDF", "Only cold site contract"], 1,
                "Correct. Match source. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_06d", "False negative risk if you over-tune:",
                ["None", "You suppress real attacks with the noise",
                 "Faster patching", "Better RTO automatically"], 1,
                "Correct. Balance. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    pbq_source = {
        "id": "pbq_d4_source",
        "kind": "map",
        "title": "Pick the data source",
        "prompt": "Map each Boundry alert hypothesis to the first source you open.",
        "categories": [
            {"id": "signin", "label": "SigninLogs / 4625 identity"},
            {"id": "edr", "label": "EDR process / endpoint"},
            {"id": "fw", "label": "Firewall / network allow-deny"},
            {"id": "mail", "label": "Mailbox audit / message trace"},
        ],
        "items": [
            {"id": "spray", "text": "30 users failing from one IP in 10 minutes", "answer": "signin"},
            {"id": "macro", "text": "excel.exe spawned powershell -enc", "answer": "edr"},
            {"id": "rdp", "text": "ALLOW 3389 from internet to PROD-DC01", "answer": "fw"},
            {"id": "bec", "text": "New external forward-all inbox rule on cfo@", "answer": "mail"},
        ],
        "explain": (
            "Correct. Source selection is Domain 4 ops skill: table-first thinking. Common trap:"
            "near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_07_siem_tools", "d4_operations", "4.4",
        "SIEM, EDR, and log tooling", 18,
        ["SIEM", "EDR", "NetFlow", "Packet Capture", "SOAR"],
        [
            ("Tool roles", """
                SIEM aggregates and correlates logs across sources. EDR focuses on endpoints (process trees, isolate). SOAR automates repeatable response steps. Know which tool answers which question.

                Where you see this at work: identity spray → SIEM plus SigninLogs. excel→powershell → EDR. auto-enrich WHOIS and open ticket → SOAR. Firewall ALLOW hunt → firewall logs plus SIEM. Mailbox forward → mailbox audit / unified audit log.

                In Security+ terms, that is monitoring tool roles and when to use each.

                Tool map:
                  SIEM: correlation, history, multi-source queries (SPL/KQL habits)
                  EDR: process tree, isolate, host IOCs, hash hunt
                  NDR/firewall/VPN: path ALLOW/DROP, remote access
                  Identity logs: AuthN patterns (462x, SigninLogs)
                  Mail tooling: rules, forwards, phishing delivery
                  SOAR: automate enrich/notify/contain with guardrails

                Technical specifics:
                - Identity pattern → SigninLogs / 4625 and 4624 / SIEM aggregate by src_ip
                  - Execution chain → EDR parent/child + command line
                  - Path open/blocked → firewall / VPN / NSG
                  - Mailbox persistence → mailbox audit / UAL (New-InboxRule, forward)
                  - Retention matters: 7-day keep may erase the BEC staging window
                  - Wrong-tool answers are classic near-misses on the exam

                Worked example:
                Question asks for best place to confirm excel.exe launched powershell.exe -enc:
                  - EDR process tree (or equivalent endpoint telemetry)
                  - Not firewall alone, not AUP poster, not CVSS PDF
                Contrast: 30-user failures from one IP → identity/SIEM aggregation first.

                                More desk clues:
                  - Identity pattern → SigninLogs/462x/SIEM aggregate.
                  - Execution chain → EDR process tree.
                  - Path open/blocked → firewall/VPN.
                  - Mailbox persistence → mailbox audit / unified audit.
                  - Wrong-tool answers are classic near-misses on the exam.

                How to answer on the exam:
                1. Ask what evidence you need.
                  2. Pick the tool that holds that evidence.
                  3. Correlate across tools when the story spans planes.

                Common trap: using only firewall logs for a mailbox forward BEC. Near-miss: naming a vendor brand without saying which evidence pane you open.

                Remember: Pick the tool that holds the evidence the question needs.
                """),
            ("Do the job CTAs", """
                Where you see this at work: Boundry CTAs: SPL Learn, KQL Learn, SOAR Lab, Shift Sim.

                In Security+ terms, that is practicing tool use as part of ops learning.

                Practice map: identity hunts in SPL/KQL, containment playbooks in SOAR, queue reps in Shift Sim.

                Technical specifics:
                - Tool skill without triage judgment still fails interviews
                  - Judgment without tool paths fails exams that ask for sources
                  - NetFlow/proxy helps east-west and egress when EDR is thin

                Worked example:
                Interview line that works: I aggregate failures by source IP in the SIEM, hunt success, then confirm host process trees in EDR before isolate.

                How to answer on the exam:
                1. Name tool + purpose.
                  2. Name next pivot.
                  3. Keep ticket evidence.

                Common trap: brand-name dropping without saying what evidence you pull.

                Remember: Purpose first, product second.
                """),
        ],
        [
            _mc("Best tool to isolate WS-HR-03 quickly?",
                ["Only NetFlow archive", "EDR isolation action",
                 "Only cold site", "Only AUP"], 1,
                "Endpoint control plane.",
                "Correct. EDR is built for host containment. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("SIEM primary ops role?",
                ["Replace all EDR", "Correlate multi-source alerts for the queue",
                 "Open RDP", "Patch hypervisors"], 1,
                "Correlation."),
            _mc("When PCAP first?",
                ["Every INFO alert", "When payload evidence is required and scoped",
                 "Instead of tickets", "To disable MFA"], 1,
                "Costly; be deliberate."),
        ],
        [
            _qz("q_d4_07a", "NetFlow helps you see:",
                ["Process trees", "Connection metadata between hosts",
                 "Mailbox rules", "BitLocker keys"], 1,
                "Correct. Who talked. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_07b", "SOAR without human gate risk:",
                ["None", "Collateral lockouts / over-automation",
                 "Faster TLS", "Better RPO magic"], 1,
                "Correct. Automate carefully. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_07c", "SPL/KQL practice maps to:",
                ["4.4 monitoring skill", "Only Domain 1 posters",
                 "Only physical", "Only cold sites"], 0,
                "Correct. Analyst query craft. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_07d", "Multi-source correlation example:",
                ["Firewall ALLOW + identity success + EDR child process",
                 "Only toner SNMP", "Only font color", "Only CHG title"], 0,
                "Correct. Join the story. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_07e", "Best first pane for excel.exe → powershell.exe -enc?",
                ["Firewall ALLOW table only", "EDR process tree / endpoint telemetry",
                 "AUP poster", "CVSS PDF"], 1,
                "Correct. Execution chain lives on the endpoint. Common trap: firewall-only "
                "answers for a parent/child question. Remember: pick the tool that holds the evidence."),
        ],
        pbq_source,
        job_ctas="d4",
    )

    add(
        "sp_d4_08_tune_capabilities", "d4_operations", "4.5",
        "Modify enterprise capabilities (tune the stack)", 17,
        ["Allow List", "Block List", "Alert Tuning", "Configuration Change"],
        [
            ("Tune, don't just watch", """
                Enhancing capabilities means tuning rules, adding detections, and closing coverage gaps on purpose. Watching a noisy console is not the goal.

                Where you see this at work: Failed Logon Burst is too noisy on scanner nights, so you exclude JUMP-01 with CHG linkage and a time window. You add a detection for external forward rule creation after a BEC. You re-test with a known true-positive case.

                In Security+ terms, that is modifying enterprise detection and prevention capabilities with change discipline.

                Tune beats:
                  1. Measure false positives and false negatives
                  2. Narrow allow-lists carefully (host/identity/time)
                  3. Add detections for missed techniques
                  4. Change-control the tune
                  5. Re-verify with test cases

                Technical specifics:
                - Narrow exclusions (JUMP-01 + CHG window) beat excluding a whole /8 forever
                  - Add detections from real incidents: external forward rules, Office→PS, legacy auth success
                  - Preventive tunes (ASR, Conditional Access) need stakeholder verify
                  - Detection content is production: reason, review, rollback
                  - Over-tuning that hides real spray creates false negatives (missed attacks)

                Worked example:
                Good tune: scanner identity exclusion documented in CHG-512, re-tested next window. Bad tune: disable the spray rule because it is noisy. After BEC: add forward-rule detection; do not only write a poster.

                                More desk clues:
                  - Narrow exclusions (host/identity/time window) beat /8 forever.
                  - Add detections from real incidents (external forward rule creation, Office→PS).
                  - Change-control detection edits like production code: reason, review, rollback.
                  - Re-test with a known true-positive case after tuning.

                How to answer on the exam:
                1. Prefer narrow exceptions.
                  2. Document and verify.
                  3. Never 'fix' noise by turning off crown-jewel detections.

                Common trap: disabling a noisy rule that also catches real spray. Near-miss: permanent /8 allow-list 'so the dashboard looks green.'

                Remember: Tune with evidence and ownership. Do not blind yourself.
                """),
            ("Change discipline", """
                Where you see this at work: someone edits a SIEM rule in prod with no ticket and no peer review.

                In Security+ terms, that is change management applied to detection content.

                Detection changes need: reason, peer review when possible, rollback, test.

                Technical specifics:
                - Version detections when you can (git or platform history)
                  - Break-glass urgent blocks still get an after-action ticket
                  - Re-test with a known true-positive case after tuning

                Worked example:
                Undocumented rule edit that drops 3389 alerts is an ops failure even if meant well. Restore, ticket, peer review.

                How to answer on the exam:
                1. Demand ticket and reason.
                  2. Prefer reversible tunes.
                  3. Test after change.

                Common trap: cowboy tuning without rollback.

                Remember: Detection content is production. Treat it like production.
                """),
        ],
        [
            _mc("After confirmed spray, best capability modify?",
                ["Delete SIEM", "Block source / tighten lockout / hunt successes + document",
                 "Open 3389", "Disable MFA"], 1,
                "Hardening from lessons."),
            _mc("Allow-listing JUMP-01 without CHG link is:",
                ["Risky tuning drift", "Perfect forever", "Required open RDP", "A honeypot"], 0,
                "Document exceptions."),
            _mc("Over-aggressive lockout after spray caused collateral. Ops fix?",
                ["Disable all security", "Tune thresholds + exception path; keep containment on real targets",
                 "Ignore users", "Delete accounting"], 1,
                "Balance."),
        ],
        [
            _qz("q_d4_08a", "Purpose of 4.5-style modifications:",
                ["Leave stack static forever", "Improve controls based on what incidents taught you",
                 "Only hire posters", "Open management ports"], 1,
                "Correct. Continuous improvement. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_08b", "Block list update should be:",
                ["Undocumented forever", "Tracked with owner/context",
                 "Random", "Only verbal"], 1,
                "Correct. Auditability. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_08c", "False negative from over-tuning means:",
                ["Good", "Real attacks suppressed: revisit the change",
                 "RTO met", "Encryption done"], 1,
                "Correct. Measure impact. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_08d", "Legacy auth disable after BEC is:",
                ["Capability modification that closes a path", "Only Domain 2 vocab",
                 "Physical only", "Irrelevant"], 0,
                "Correct. Enterprise change. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    pbq_iam = {
        "id": "pbq_d4_iam",
        "kind": "pick",
        "title": "IAM ops after spray",
        "prompt": (
            "Spray from one IP hit 30 accounts; three had password spray successes. "
            "What IAM ops package fits?"
        ),
        "choices": [
            {"id": "pkg", "text": "Reset/revoke those sessions, enforce MFA, block IP, review privileged group adds, watch for new inbox rules"},
            {"id": "ignore", "text": "Ignore successes; failures are enough"},
            {"id": "rdp", "text": "Grant the attacking IP VPN as honeypot"},
            {"id": "off", "text": "Disable MFA so users stop calling"},
        ],
        "answer": "pkg",
        "explain": (
            "Correct. Successes are the incident. IAM ops = sessions, secrets, MFA, privilege watch."
            "Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_09_iam_ops", "d4_operations", "4.6",
        "IAM operations on the shift", 18,
        ["MFA", "SSO", "Federation", "Privileged Access", "Just-In-Time"],
        [
            ("Daily IAM, not slides", """
                IAM operations means running identity day to day: joiners, movers, leavers, MFA, roles, and access reviews. Identity is often the real perimeter.

                Where you see this at work: disable accounts on termination day, require MFA for remote admin, review Entra privileged roles monthly, kill legacy auth that skips prompts, and keep break-glass accounts monitored and rarely used.

                In Security+ terms, that is identity and access management operations.

                IAM ops map:
                  1. Provision / deprovision promptly (SLA, not heroes)
                  2. MFA and Conditional Access
                  3. Least privilege / JIT (just-in-time) where possible
                  4. Access reviews on privileged roles
                  5. Service account hygiene (no interactive daily-driver DA)

                Technical specifics:
                - Standing Global Admin / Domain Admin for daily mail is an ops failure
                  - Disable legacy auth; monitor for breakage with a backout plan
                  - Joiner/mover/leaver SLAs beat quarterly cleanup heroes
                  - Break-glass: long random secrets, monitored, alert on use, offline procedure
                  - After BEC: revoke sessions/refresh tokens, reset, review mailbox permissions and privileged group adds (4728/Directory Audit)

                Worked example:
                CFO mailbox compromised via legacy auth. Contain: revoke sessions, reset, kill malicious forward. IAM ops follow-up: disable legacy auth org-wide with monitoring, Conditional Access harden, privileged role review. Poster-only fails.

                                More desk clues:
                  - Joiner/mover/leaver SLAs beat quarterly cleanup heroes.
                  - Standing Global Admin / Domain Admin for daily mail is an ops failure.
                  - Disable legacy auth and monitor for breakages with a backout.
                  - Access reviews on privileged roles are IAM ops, not optional paperwork.

                How to answer on the exam:
                1. Look for lifecycle and privilege clues.
                  2. Prefer least privilege + MFA answers.
                  3. Keep AuthN (prove who) vs AuthZ (what they may do) separate when asked.

                Common trap: shared admin passwords in a spreadsheet as 'ops pragmatism.' Near-miss: quarterly access review theater while leavers stay enabled for weeks.

                Remember: IAM ops closes the paths Domain 2 keeps exploiting.
                """),
            ("801 IAM: passkeys, passwordless, JIT, emergency access", """
                Where you see this at work: staff move from SMS OTP to passkeys (device-bound
                phishing-resistant credentials). Privileged roles use just-in-time (JIT)
                elevation instead of standing Global Admin. Emergency access (break-glass)
                accounts sit offline, monitored, and unused until IdP outage day.

                In Security+ terms, that is SY0-801 identity and access management depth:
                passkeys / passwordless, JIT access, and emergency access accounts.

                Define before use:
                  - Passwordless: prove identity without typing a reusable password (passkey,
                    platform authenticator, certificate patterns)
                  - Passkey: public-key credential tied to a device/authenticator, resistant
                    to classic phishing of passwords and many OTP steals
                  - JIT access: elevate for a short window when needed, then remove standing
                    privilege automatically
                  - Emergency access account: rare break-glass identity for IdP/MFA outages,
                    not a daily admin mailbox

                Technical specifics:
                  - Passkeys reduce password-spray payoff; still enroll recovery and device loss
                    procedures.
                  - JIT/PAM: eligible roles beat permanent Owner on every subscription.
                  - Emergency access: long random secrets or hardware keys, exclude from
                    routine Conditional Access carefully, alert on any use, dual control.
                  - Deprovision leavers same day; stale cloud apps and OAuth grants linger.

                Worked example:
                Exam-shaped ask: reduce phishing of admin passwords for cloud console.
                Strong answer class: phishing-resistant passwordless/passkey for admins plus
                JIT for elevation. Near-miss: SMS OTP forever with standing Global Admin.

                How to answer on the exam:
                  1. Match passkey/passwordless to phishing-resistant AuthN.
                  2. Match JIT to shrinking standing privilege.
                  3. Match emergency access to rare, monitored break-glass, not daily use.

                Common trap: calling SMS OTP "passwordless." Near-miss: break-glass used for
                everyday admin work so nobody waits on JIT.

                Remember: Passkeys resist phish. JIT shrinks standing power. Break-glass is rare.
                """),
        ],
        [
            _mc("After spray successes, IAM priority?",
                ["Ignore", "Reset/revoke sessions, MFA, block source, watch privilege",
                 "Open RDP", "Disable logging"], 1,
                "Contain identity.",
                "Correct. Successful auth is the fire. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Just-in-time admin purpose?",
                ["Standing domain admin for all", "Time-bound elevation: shrink standing privilege",
                 "Open 3389", "Delete SIEM"], 1,
                "Least privilege ops.",
                "Correct. JIT shrinks standing privilege. "
                "Common trap: standing Domain Admin for convenience. "
                "Remember: elevate briefly, then drop."),
            _mc("Federation trust misconfig risk?",
                ["None", "Auth decisions outsourced to a weak/wrong IdP path",
                 "Only toner", "Only RPO"], 1,
                "Trust carefully.",
                "Correct. Federation trusts carefully. "
                "Common trap: answers that ignore the IdP path. "
                "Remember: wrong trust equals wrong AuthN."),
            _mc("Best upgrade path away from phishable admin passwords?",
                ["SMS OTP with standing Global Admin forever",
                 "Passkeys/passwordless for admins plus JIT elevation",
                 "Shared spreadsheet of Domain Admin passwords",
                 "Disable all MFA prompts permanently"], 1,
                "Phishing-resistant AuthN plus least privilege.",
                "Correct. Passkeys plus JIT beat SMS and standing GA. "
                "Common trap: SMS labeled as passwordless. "
                "Remember: resist phish and shrink standing rights."),
        ],
        [
            _qz("q_d4_09a", "Session revoke after BEC:",
                ["Optional wallpaper", "Core IAM containment",
                 "Only Domain 3", "Physical only"], 1,
                "Correct. Kill tokens. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_09b", "SSO benefit with strong MFA:",
                ["Weaker auth", "Central authn with consistent controls",
                 "Open RDP", "Disable accounting"], 1,
                "Correct. Centralize control. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_09c", "Break-glass account should be:",
                ["Used daily quietly", "Rare, monitored, alerted",
                 "Shared on Slack", "Password Summer2026!"], 1,
                "Correct. Emergency only. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_09d", "Unexpected privileged group add at 03:14:",
                ["Normal CHG without ticket", "Investigate as incident-shaped IAM event",
                 "Ignore", "Open more ports"], 1,
                "Correct. Privilege change monitoring. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_09e", "A passkey is best described as:",
                ["A shared seasonal password in chat", "A phishing-resistant device-bound credential",
                 "A firewall ANY/ANY exception", "A honeypot file on a share"], 1,
                "Correct. Passkeys are public-key style credentials tied to authenticators. "
                "Common trap: equating SMS OTP with passkeys. "
                "Remember: phishing-resistant AuthN."),
        ],
        pbq_iam,
        job_ctas="d4",
    )

    # 801 deeper drill for 4.5 passkeys / JIT / gMSA (after baseline IAM ops).
    register_d4_801_passkeys_jit(add, _mc, _qz)

    pbq_soar = {
        "id": "pbq_d4_soar",
        "kind": "pick",
        "title": "SOAR collateral",
        "prompt": (
            "SOAR auto-locked three accounts after spray; one had a legitimate password change. "
            "Best ops move?"
        ),
        "choices": [
            {"id": "human", "text": "Validate lockouts, restore the false victim carefully, keep containment on real targets, escalate the edge case"},
            {"id": "off", "text": "Disable SOAR forever so no one gets locked"},
            {"id": "rdp", "text": "Re-open inbound 3389 as compensation"},
            {"id": "fp", "text": "Close all three as Defender scan FPs"},
        ],
        "answer": "human",
        "explain": (
            "Correct. Automation with an exception path. Collateral is an IR task, not an excuse to"
            "stop containing. Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_10_automation_soar", "d4_operations", "4.7",
        "Automation and SOAR with a human gate", 18,
        ["SOAR", "Playbook", "Orchestration", "Human Gate"],
        [
            ("Automate the repeatable", """
                SOAR means security orchestration, automation, and response. It stitches tools together and automates repeatable steps. Humans still approve destructive actions when confidence or impact is high.

                Where you see this at work: playbook auto-enriches spray IPs, opens a ticket with standard fields, and suggests a firewall block. A human clicks approve before the change. High-confidence EDR isolate may auto-run with guardrails and audit logs.

                In Security+ terms, that is automation and orchestration with human gates.

                SOAR beats:
                  1. Automate enrich / notify / ticket first
                  2. Gate high-impact contain (disable user, wide block, mass isolate)
                  3. Measure time saved and error rate
                  4. Keep playbooks under change control
                  5. Idempotent steps + rate limits + kill switch

                Technical specifics:
                - Bad automation: auto-disable VIP accounts on every travel false positive
                  - Good automation: enrich + consistent ticket fields + optional contain
                  - Log every automated action for IR timelines and audit
                  - Map playbooks to IR phases (enrich in analysis, isolate in containment)
                  - Confidence thresholds and allow-lists prevent ticket storms

                Worked example:
                Auto-block every foreign MFA success without context creates availability outages for travelers. Better: enrich geo/device/MFA detail, open ticket, human approve block when spray/BEC pattern matches. Runaway playbook opening 200 duplicate tickets is itself an incident.

                                More desk clues:
                  - Automate enrich, ticket fields, notifications first.
                  - Gate disable-user / firewall-block / isolate behind confidence + human approve when impact is high.
                  - Idempotent playbooks with rate limits prevent ticket storms.
                  - Log every automated action for audit and IR timelines.

                How to answer on the exam:
                1. Automate toil first.
                  2. Gate destructive steps.
                  3. Prefer consistent evidence packs and audit logs.

                Common trap: fully automatic account wipe on every anomaly with no confidence check. Near-miss: SOAR as an excuse to remove analysts on day one.

                Remember: Automate the repeatable. Gate the irreversible.
                """),
            ("Failure mode", """
                Where you see this at work: playbook loops and opens 200 duplicate tickets overnight.

                In Security+ terms, that is safe automation design and failure handling.

                Failure beats: idempotency, rate limits, dead-letter handling, kill switch for playbooks, staging tests when possible.

                Technical specifics:
                - Monitor automation like a production app (error rate, loop detection)
                  - Rollback path for bad blocks/disables
                  - Keep humans in the loop for crown-jewel identity actions

                Worked example:
                A runaway playbook is an availability and trust incident inside the SOC. Kill switch, fix the loop, after-action with change control.

                How to answer on the exam:
                1. Look for human gate + rollback.
                  2. Reject untested destructive automation.
                  3. Keep audit logs of automated actions.

                Common trap: SOAR as excuse to remove analysts entirely on day one.

                Remember: Automation without guardrails becomes the incident.
                """),
            ("801 automation: agentic AI, chatbots, guardrails", """
                Where you see this at work: a chatbot drafts ticket summaries. An agentic
                AI playbook proposes firewall blocks and can call APIs without a human if
                you let it. AI-augmented baselines flag odd login volumes. Without guardrails,
                the agent disables VIP accounts on every travel anomaly.

                In Security+ terms, that is SY0-801 automation with AI capabilities: agentic
                systems, chatbots, predictive analysis, AI-augmented baselines, and the
                guardrails that keep them safe.

                Define before use:
                  - Chatbot: conversational assistant that drafts or answers; usually low
                    direct change power
                  - Agentic AI: automation that can plan and call tools/APIs toward a goal
                  - Guardrails: limits on what automation may do (allow lists, approvals,
                    rate limits, kill switches, scoped credentials)
                  - AI-augmented baseline: model-assisted normal/abnormal detection that still
                    needs tuning and human review

                Technical specifics:
                  - Start agents in suggest mode; promote to act only with scoped tokens.
                  - Log prompts, tool calls, and outcomes for audit (privacy-aware).
                  - Pair with objective 2.6 threats: prompt injection against an agent with
                    tools is a high-impact path.
                  - Predictive / baseline AI can raise speed; false positives still need gates.
                  - Intended outcomes: efficiency, enforcing baselines, less downtime, more
                    proactive SecOps, not unsupervised production wipe.

                Worked example:
                Agentic SOAR reads a phishing mail and is about to auto-purge 5,000 mailboxes.
                Best ops move: hard guardrail + human approve for mass mail actions; keep
                enrich/ticket automatic. Near-miss: "the AI is smart, let it run."

                How to answer on the exam:
                  1. Separate chatbot draft help from agentic tool actions.
                  2. Prefer guardrail answers for high-impact automation.
                  3. Keep change control and rollback for AI-driven playbooks.

                Common trap: treating any AI feature as automatically safe. Near-miss:
                removing human gates because "agentic" sounds modern.

                Remember: Agents need guardrails. Suggest first. Act only with limits.
                """),
        ],
        [
            _mc("SOAR locked three accounts; one legit password change. Best move?",
                ["Disable SOAR forever", "Validate, restore false victim carefully, keep real containment",
                 "Open 3389", "Close all as Defender FP"], 1,
                "Human gate on collateral.",
                "Correct. Do not undo the whole contain. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Good first SOAR automation?",
                ["Format C: on any alert", "Enrich + ticket + notify on high-confidence use cases",
                 "Disable MFA org-wide", "Delete logs"], 1,
                "Low regret actions first.",
                "Correct. Start with low-regret automation. "
                "Common trap: destructive first steps. "
                "Remember: enrich and ticket before mass contain."),
            _mc("Orchestration means roughly:",
                ["One tool only", "Coordinating multiple tools/actions in a playbook",
                 "Only posters", "Only physical"], 1,
                "Glue.",
                "Correct. Orchestration coordinates tools. "
                "Common trap: one-tool-only answers. "
                "Remember: playbooks glue systems together."),
            _mc("Agentic AI that can call firewall APIs without limits is mainly missing?",
                ["A prettier chatbot theme", "Guardrails, scoped credentials, and human gates",
                 "More standing Domain Admin rights", "Open inbound RDP for speed"], 1,
                "AI automation needs limits.",
                "Correct. Guardrails bound agentic actions. "
                "Common trap: trusting the model without scopes. "
                "Remember: agents need allow lists and approvals."),
        ],
        [
            _qz("q_d4_10a", "Human gate purpose:",
                ["Slow everything randomly", "Prevent high-impact automation mistakes",
                 "Open RDP", "Skip tickets"], 1,
                "Correct. Approve contain that hurts. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_10b", "Playbook should include:",
                ["No rollback", "Clear steps, conditions, exception path",
                 "Only memes", "Hardcoded domain admin password"], 1,
                "Correct. Operable runbook. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_10c", "SOAR after BEC might auto:",
                ["Revoke sessions / disable rule with approval", "Wire fraud complete",
                 "Open 3389", "Turn off mailbox audit"], 0,
                "Correct. Contain actions. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_10d", "Metric for SOAR success:",
                ["More random lockouts", "Faster consistent response with acceptable error rate",
                 "Zero tickets", "No logging"], 1,
                "Correct. Speed + quality. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_10e", "Agentic AI in SecOps is safest when:",
                ["It has unrestricted API keys and no approvals",
                 "Guardrails, scoped credentials, and human gates bound its actions",
                 "It replaces all access reviews permanently",
                 "It opens inbound RDP to speed enrichment"], 1,
                "Correct. Agentic tools need limits like any privileged automation. "
                "Common trap: unsupervised production changes. "
                "Remember: suggest first, act with guardrails."),
        ],
        pbq_soar,
        job_ctas="d4",
    )

    # 801 deeper drill for 4.6 agentic AI guardrails (after baseline SOAR).
    register_d4_801_agentic_guardrails(add, _mc, _qz)

    pbq_ir = {
        "id": "pbq_d4_ir",
        "kind": "order",
        "title": "Order the BEC response",
        "prompt": (
            "Confirmed: cfo@ has external forward-all, East EU IP, legacy auth, no MFA. "
            "Finance has vendor-payment change in draft. Order the response activities."
        ),
        "items": [
            {"id": "analyze", "text": "Analysis: confirm rule, sessions, message trace, payment-change mail"},
            {"id": "contain", "text": "Contain: revoke sessions, disable/reset account, remove rule, warn finance"},
            {"id": "eradicate", "text": "Eradicate: hunt other mailboxes, kill legacy auth / app passwords"},
            {"id": "recover", "text": "Recover: restore access with MFA, monitor SigninLogs, contact vendors"},
            {"id": "lessons", "text": "Lessons: ticket + MITRE, CA/DLP tune, awareness for finance"},
        ],
        "correct_order": ["analyze", "contain", "eradicate", "recover", "lessons"],
        "explain": (
            "Correct. Analyze → contain → eradicate → recover → lessons. Recovery before containment"
            "keeps the forward rule alive. Common trap: near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_11_ir_phases", "d4_operations", "4.8",
        "Incident response phases you will order", 18,
        ["Incident Response", "Containment", "Eradication", "Recovery", "Lessons Learned"],
        [
            ("The sequence", """
                Incident response phases are a standard order of work. CompTIA-style sequences commonly include preparation, detection and analysis, containment, eradication, recovery, and lessons learned.

                Where you see this at work: malware on HR PC: detect in EDR, contain by isolate, eradicate persistence and malicious mail rules, recover to known-good image with monitoring, then lessons learned that add ASR and fix the mail path.

                In Security+ terms, that is IR phase order and what belongs in each phase.

                Phase map:
                  1. Preparation (before the fire): playbooks, contacts, tooling, authority
                  2. Detection and analysis
                  3. Containment (stop spread)
                  4. Eradication (remove cause)
                  5. Recovery (restore safely)
                  6. Lessons learned / post-incident

                Technical specifics:
                - Containment examples: isolate host, revoke sessions/tokens, block hash/IP, disable malicious inbox rule, sinkhole domain
                  - Eradication examples: remove persistence, disable legacy auth, delete malware, reset credentials, patch the entry hole
                  - Recovery examples: reimage, restore from known-good backup, re-enable with heightened monitoring, validate RTO targets if business services
                  - Contain before deep forensics when spread is active
                  - Preparation failures show up as missing isolate authority or dead tooling

                Worked example:
                Live ransomware encrypting a finance share:
                  - Wrong: leave host online overnight to 'analyze,' or jump to lessons-learned posters
                  - Right order: detect/analyze enough to act → contain (isolate, revoke, block) → eradicate → recover → lessons learned (ASR, backup immutability, path fix)
                BEC with active forward: contain the mailbox path before writing the novel.

                                More desk clues:
                  - Containment examples: isolate host, revoke sessions, block hash/IP, disable rule.
                  - Eradication examples: remove persistence, disable legacy auth, delete malicious inbox rule.
                  - Recovery examples: reimage, restore, re-enable with heightened monitoring.
                  - Preparation failures show up as missing isolate authority or dead tooling.

                How to answer on the exam:
                1. Identify the phase the question asks for.
                  2. Do not jump to lessons learned before contain.
                  3. Preparation answers only when the story is before the incident.

                Common trap: recovery before containment, or lessons-learned posters as the first response to live BEC. Near-miss: calling detection 'preparation' because dashboards look ready.

                Remember: Detect → contain → eradicate → recover → learn. Prep before all of it.
                """),
            ("Preparation", """
                Where you see this at work: no call tree, no isolate authority, EDR licenses expired.

                In Security+ terms, that is preparation as the phase that makes the other phases possible.

                Prep checklist: roles, playbooks, tooling health, evidence handling, management buy-in, tabletop exercises, legal/comms contacts.

                Technical specifics:
                - Tabletop exercises are preparation (people/decision gaps)
                  - Break-glass and isolate authority must exist before 02:00
                  - Tooling health: EDR agents reporting, SIEM ingest, backup restore tested

                Worked example:
                If analysts cannot isolate without a three-day debate, preparation failed. Fix authority and tooling before the next fire.

                How to answer on the exam:
                1. When the question is pre-incident, pick preparation.
                  2. After ignition, pick the active phase.
                  3. Keep order straight.

                Common trap: calling detection 'preparation' because dashboards look ready.

                Remember: Preparation is before the ticket. Containment is during the fire.
                """),
        ],
        [
            _mc("After confirming Invoice.xlsm → -enc, wrong first IR move?",
                ["Isolate and preserve", "Leave host on LAN to see if files encrypt overnight",
                 "Escalate", "Pull EDR tree into ticket"], 1,
                "Containment before curiosity.",
                "Correct. Watching ransomware finish is not analysis. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("Correct high-level IR order after analysis?",
                ["Recover → contain", "Contain → eradicate → recover → lessons",
                 "Lessons → ignore contain", "Open RDP → recover"], 1,
                "Classic sequence."),
            _mc("Preparation includes:",
                ["Only hoping", "Playbooks, contacts, logging, roles practiced",
                 "Deleting SIEM", "Disabling MFA"], 1,
                "Before the fire."),
        ],
        [
            _qz("q_d4_11a", "Containment goal:",
                ["Write the novel first", "Stop spread / reduce impact now",
                 "Only patch next year", "Open more ports"], 1,
                "Correct. Stop the bleeding. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_11b", "Eradication means:",
                ["Ignore persistence", "Remove attacker footholds/causes",
                 "Only restore from backup blindly", "Disable accounting"], 1,
                "Correct. Clean the roots. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_11c", "Recovery includes:",
                ["Restoring service securely and monitoring for re-entry", "Re-opening 3389",
                 "Skipping MFA", "Deleting tickets"], 0,
                "Correct. Safe return. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_11d", "Lessons learned feeds:",
                ["Trash only", "Detection tuning, training, risk register, architecture fixes",
                 "Only toner orders", "Attacker blogs exclusively"], 1,
                "Correct. Improve the program. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_11e", "Best phase order after confirmed malware execution on a live host?",
                ["Lessons learned, then maybe contain tomorrow",
                 "Contain, then eradicate, then recover, then lessons learned",
                 "Recovery first so users are happy, contain later",
                 "Preparation only, because dashboards look ready"], 1,
                "Correct. Stop spread before cleanup novels. Common trap: recovery or "
                "lessons-learned posters before containment. "
                "Remember: contain → eradicate → recover → learn."),
        ],
        pbq_ir,
        job_ctas="d4",
    )

    add(
        "sp_d4_12_ir_comms_docs", "d4_operations", "4.8",
        "IR communications and documentation", 17,
        ["Incident Communication", "Chain of Custody", "Ticket Hygiene", "Legal Hold"],
        [
            ("Who needs to know", """
                IR communications and documentation keep the right people informed without leaking chaos or secrets. The ticket is the single source of truth.

                Where you see this at work: finance and legal need BEC payment-risk heads-up early. Executives get clear status, not raw malware samples in email. Users get safety notices on approved channels. The ticket holds timeline, actions, and IOCs.

                In Security+ terms, that is incident communications, escalation paths, and evidence documentation.

                Comms beats:
                  1. Need-to-know + role-based updates
                  2. Single source of truth ticket
                  3. Preserve evidence / chain-of-custody ideas
                  4. External comms via approved spokespeople when required

                Technical specifics:
                - Audience map: finance for payment risk, legal/leadership for material incidents, users for safety notices via approved channels
                  - Ticket timeline fields: detect time, contain time, eradicate time, recover time
                  - Do not paste live malware or secrets into open chat
                  - Preserve EDR exports/hashes before casual reimage when analysis still matters
                  - Regulatory notice may overlap Domain 5; escalate up when clocks start

                Worked example:
                BEC with invoice-change language in drafts:
                  - Tell finance early about payment risk (do not wait for a perfect report)
                  - Document revoke sessions, rule removal, IOCs in the ticket
                  - Wrong: public social posts mid-incident, or zero notes so nobody can learn

                                More desk clues:
                  - Audience map: finance for payment risk, legal/leadership for material incidents, users for safety notices via approved channels.
                  - Ticket timeline fields: detect, contain, eradicate, recover.
                  - Preserve EDR exports/hashes before casual reimage when analysis still matters.
                  - Do not paste live malware or secrets into open chat.

                How to answer on the exam:
                1. Match audience to message.
                  2. Document actions as you go.
                  3. Preserve evidence before cleanup when feasible.

                Common trap: public social posts mid-incident, or zero documentation so nobody can learn. Near-miss: emailing live malware samples to a wide DL.

                Remember: Right people, clear timeline, preserved evidence.
                """),
            ("Evidence", """
                Where you see this at work: someone reimages WS-HR-03 before EDR export or memory capture when the malware family is unknown.

                In Security+ terms, that is basic evidence handling inside IR docs.

                Evidence beats: collect important artifacts first when safe, note who did what when, avoid altering unnecessarily, hash samples.

                Technical specifics:
                - EDR timeline export into the ticket
                  - Hash samples; do not email live malware broadly
                  - Balance contain vs preserve: isolate can come first; capture before wipe when possible

                Worked example:
                Reimage may be right for recovery after capture. Capture-first when analysis still matters. Write the decision if you had to wipe to stop spread.

                How to answer on the exam:
                1. Balance contain vs preserve.
                  2. Document decisions.
                  3. Keep IOCs shareable safely (hashes, URLs, users).

                Common trap: destroying the only evidence to 'be fast' without noting why.

                Remember: Write down what you did. Future you is a stakeholder.
                """),
        ],
        [
            _mc("BEC with payment-change draft: who to warn early?",
                ["Nobody", "Finance / payments owners immediately after/with containment",
                 "Only the attacker", "Only toner vendor"], 1,
                "Stop the money."),
            _mc("Portfolio-style ticket fields matter because:",
                ["Fonts", "Handoffs and interviews need clear evidence + disposition",
                 "They open RDP", "They replace MFA"], 1,
                "Documentation is ops."),
            _mc("Deleting logs to 'reduce liability' during IR is:",
                ["Smart", "Destructive and likely obstructive: preserve evidence",
                 "Required", "A honeypot"], 1,
                "Do not destroy evidence."),
        ],
        [
            _qz("q_d4_12a", "Chain of custody tracks:",
                ["Who handled evidence when", "Only CPU temp", "Only RPO", "Only VLAN names"], 0,
                "Correct. Integrity of evidence. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_12b", "External comms during incident should be:",
                ["Random tweets by analysts", "Coordinated via designated roles",
                 "Silent forever always", "Only in memes"], 1,
                "Correct. Control the message. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_12c", "MITRE in the ticket helps:",
                ["Map technique for hunt/lessons", "Open 3389", "Disable SIEM", "Set RTO"], 0,
                "Correct. Shared language. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_12d", "Legal hold means ops should:",
                ["Wipe disks immediately", "Preserve relevant data as directed",
                 "Ignore counsel", "Open RDP"], 1,
                "Correct. Preserve. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    add(
        "sp_d4_13_sources_identity", "d4_operations", "4.9",
        "Investigation sources: identity and mail", 18,
        ["SigninLogs", "Mailbox Audit", "Message Trace", "Auth Logs"],
        [
            ("Build the evidence pack", """
                Data sources for investigations must match the question. Identity sources explain authentication and authorization stories (who signed in, what changed).

                Where you see this at work: spray: 4625/SigninLogs aggregates by source IP. BEC: mailbox audit plus SigninLogs. Travel: SigninLogs plus HR note. Privileged add: directory audit or 4728/4720-style clues. Always write the time window and timezone.

                In Security+ terms, that is identity investigation sources and what each proves.

                Identity sources:
                  Windows Security: 4624 success, 4625 failure, 4672 privilege, 4720/4728 group/user
                  Entra SigninLogs / AuditLogs
                  Mailbox audit / UAL for rules and forwards
                  VPN auth logs
                  Ticket / HR context for movers and travel

                Technical specifics:
                - Spray hunt: failures by IP + distinct users, then hunt 4624/success
                  - BEC: New-InboxRule / Set-Mailbox forwarding + client app / legacy flags
                  - Privilege: directory audit for group adds / new admin users
                  - Time bounds and clock skew: note UTC vs local in the ticket
                  - Export rows into the ticket; do not only keep a blurry screenshot forever
                  - Retention limits may force earlier legal-hold escalation

                Worked example:
                30 users failing from one IP → SigninLogs/SIEM identity sources, then success hunt. Inbox forward rule → mailbox audit / UAL, not pfirewall alone. Too-narrow 'last 5 minutes' window on a multi-day BEC misses staging.

                                More desk clues:
                  - Spray: aggregate failures by IP + distinct users, then hunt 4624/success.
                  - BEC: mailbox audit for New-InboxRule / forward + SigninLogs client app/legacy flags.
                  - Privilege: directory audit for group adds / new admin users.
                  - Always write the time window and timezone into the ticket.

                How to answer on the exam:
                1. Name the activity type.
                  2. Pick the source that records it.
                  3. Bound time and account on purpose.

                Common trap: firewall PCAP as the primary source for an inbox forward question. Near-miss: deleting logs mid-investigation to 'reduce noise.'

                Remember: Identity stories need identity sources.
                """),
            ("Time bounds", """
                Where you see this at work: you pull 'last 5 minutes' for a BEC that may have started days ago with legacy auth.

                In Security+ terms, that is scoping investigation windows.

                Scope: first suspicious signal backward and forward; include rule creation time and prior successes.

                Technical specifics:
                - Anchor on first IOC, then expand to related accounts and hosts
                  - Note UTC vs local; write the window in the ticket
                  - Retention may force earlier escalation for legal hold

                Worked example:
                Too-narrow windows miss staging. Too-wide windows drown you. Start from IOC time and expand with a written bound.

                How to answer on the exam:
                1. Anchor on first IOC.
                  2. Expand to related accounts/hosts.
                  3. Document the window.

                Common trap: deleting logs to 'reduce noise' mid-investigation.

                Remember: Bound the window on purpose. Write it down.
                """),
        ],
        [
            _mc("Best sources for suspected BEC forward rule?",
                ["Only pfirewall 445", "Mailbox audit/rules + SigninLogs + message trace",
                 "Only cold site contract", "Only toner"], 1,
                "Mail + identity."),
            _mc("Spray investigation minimum fields?",
                ["IP, users, failure codes, time, any successes", "Only wallpaper color",
                 "Only RPO", "Only CHG title"], 0,
                "Pattern evidence."),
            _mc("Why time-bound identity hunts?",
                ["UI fashion", "Keep queries usable and match the incident window",
                 "Disable MFA", "Open RDP"], 1,
                "Scope."),
        ],
        [
            _qz("q_d4_13a", "4625 is roughly:",
                ["Failed logon evidence on Windows", "Firewall allow",
                 "Mailbox forward", "BitLocker key"], 0,
                "Correct. Auth failures. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_13b", "Inbox rule creation log supports:",
                ["BEC persistence proof", "Only NIDS", "Only RTO", "Only physical"], 0,
                "Correct. Mail persistence. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_13c", "MFA prompt logs help decide:",
                ["Travel FP vs odd auth patterns", "Toner levels", "Cold site cost", "VLAN paint"], 0,
                "Correct. Authn context. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_13d", "Evidence pack should be:",
                ["Pasted into ticket with disposition", "Kept only in your head",
                 "Deleted after 5 minutes", "Posted publicly raw"], 0,
                "Correct. Handoff. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )

    pbq_pack = {
        "id": "pbq_d4_pack",
        "kind": "pick",
        "title": "Evidence pack choice",
        "prompt": (
            "Alert: possible malware on WS-HR-03 after Invoice.xlsm. Which evidence pack "
            "do you gather first?"
        ),
        "choices": [
            {"id": "edr", "text": "EDR process tree, file hash, parent email metadata, isolate status, user/host asset tier"},
            {"id": "onlyfw", "text": "Only 30 days of unrelated 445 DROP noise"},
            {"id": "rto", "text": "Only the cold site contract PDF"},
            {"id": "shame", "text": "Only a screenshot of shaming the user in Slack"},
        ],
        "answer": "edr",
        "explain": (
            "Correct. Endpoint execution needs EDR + mail lure context + containment state. Common trap:"
            "near-miss answers that ignore the stem's path or control class. "
        ),
    }

    add(
        "sp_d4_14_sources_endpoint_net", "d4_operations", "4.9",
        "Investigation sources: endpoint and network", 18,
        ["EDR Timeline", "Firewall Logs", "DNS Logs", "DHCP", "NetFlow"],
        [
            ("Endpoint pack", """
                Endpoint and network sources complete the investigation pack when hosts and paths matter. Endpoint tells you what ran. Network tells you where it talked.

                Where you see this at work: EDR process tree for excel→powershell, DNS/proxy for egress domains, firewall for ALLOW/DROP on 3389/22/445, NetFlow for east-west after phishing, email gateway for lure delivery.

                In Security+ terms, that is endpoint and network data sources for investigations.

                Source map:
                  EDR/syslog process: execution chain
                  Firewall/VPN/NSG: path open/used/blocked
                  DNS/proxy: callback domains
                  Email gateway: lure delivery
                  Disk/memory forensics when deeper analysis needed

                Technical specifics:
                - Endpoint pack fields: parent/child, command line, hash, user, path, egress
                  - Network pack fields: ALLOW/DROP, src/dst/port, VPN user mapping, DNS query
                  - Pair beaconing domains with the host that owns the socket
                  - If EDR is missing on a crown jewel, say the blind spot; lean on identity/network
                  - Never open more inbound management ports to 'investigate live'
                  - Syslog/HEC forwarder health is part of source reliability

                Worked example:
                Malware execution: EDR first (parent/child + hash). Internet RDP exposure: firewall rules + auth attempts (462x). Beaconing: proxy/DNS + EDR together. ALLOW 3389 with no EDR on the DC means you are partly blind; say so and isolate faster.

                                More desk clues:
                  - Endpoint pack: parent/child, command line, hash, user, path, egress.
                  - Network pack: ALLOW/DROP, src/dst/port, VPN user mapping, DNS query name.
                  - If EDR is missing on a crown jewel, say the blind spot and lean on identity/network harder.
                  - Never open more inbound management ports to "investigate live."

                How to answer on the exam:
                1. Match source to artifact.
                  2. Corroborate across planes.
                  3. Keep containment priority.

                Common trap: network-only conclusions for a clear endpoint parent/child chain. Near-miss: pretending coverage exists when the agent is missing.

                Remember: Endpoint tells you what ran. Network tells you where it talked.
                """),
            ("Network pack", """
                Where you see this at work: ALLOW 3389 row plus no EDR on the DC means you are partly blind.

                In Security+ terms, that is recognizing coverage gaps as part of source selection.

                If a source is missing, say the gap, compensate with adjacent logs, and open a coverage ticket after containment.

                Technical specifics:
                - Blind spots are Domain 4 findings too
                  - Forwarder health and retention affect what you can prove later
                  - VPN logs map remote user to source IP when edge logs only show the concentrator

                Worked example:
                No EDR on a crown jewel forces heavier network/identity reliance and faster isolation decisions. Document the gap; do not invent process trees.

                How to answer on the exam:
                1. Name best source.
                  2. Name fallback if missing.
                  3. Document blind spots.

                Common trap: pretending coverage exists when the agent is missing.

                Remember: Missing telemetry is a finding. Say it out loud.
                """),
        ],
        [
            _mc("Malware on WS-HR-03: first evidence pack?",
                ["Only unrelated 445 DROPs", "EDR tree + hash + mail metadata + isolate status",
                 "Only cold site PDF", "Only shame screenshot"], 1,
                "Endpoint + lure.",
                "Correct. Match sources to execution. Common trap: answers that ignore containment, ownership, or the open path. "),
            _mc("DHCP logs help when:",
                ["You need hostname↔IP mapping in a window", "You want open RDP",
                 "You disable EDR", "You set RPO"], 0,
                "Identity of the host on the wire."),
            _mc("DNS logs can reveal:",
                ["C2 domains / odd resolutions", "BitLocker keys", "Only AUP text", "Only badges"], 0,
                "Name callbacks."),
        ],
        [
            _qz("q_d4_14a", "Command line in EDR matters because:",
                ["It shows tradecraft (-enc, downloads)", "It sets RTO",
                 "It opens 3389", "It replaces MFA"], 0,
                "Correct. Args tell intent. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_14b", "Firewall ALLOW to DC should be pulled with:",
                ["Source IP, time, dest, rule, any auth follow-on", "Only toner",
                 "Only posters", "Only RPO"], 0,
                "Correct. Full row context. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_14c", "NetFlow after phishing helps spot:",
                ["Lateral connection patterns", "Mailbox rules", "BitLocker recovery", "AUP typos"], 0,
                "Correct. East-west. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_14d", "Isolate status belongs in the pack because:",
                ["Containment state changes next steps", "Fonts", "Only Domain 5", "Only cold site"], 0,
                "Correct. Know if blast radius is limited. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        pbq_pack,
        job_ctas="d4",
    )

    add(
        "sp_d4_15_investigation_pack", "d4_operations", "4.9",
        "Build the handoff pack", 18,
        ["Investigation", "IOC", "Timeline", "Disposition"],
        [
            ("What good looks like", """
                An investigation pack is the evidence bundle another analyst or manager can reuse without a hallway conversation.

                Where you see this at work: ticket with What / Why / Disposition / technique notes / IOCs / actions / next steps. Exported log rows plus screenshots. Clear TP vs FP reason with CHG links for scanner cases.

                In Security+ terms, that is building a complete investigation documentation pack.

                Pack contents:
                  1. Summary in plain English
                  2. Timeline (detect / contain / eradicate / recover)
                  3. Sources consulted
                  4. IOCs (hashes, IPs, users, rules)
                  5. Actions taken + who/when
                  6. Disposition and follow-up (tune, patch, harden, owner)

                Technical specifics:
                - Include negative findings ('no successful 4624 from attacking IP')
                  - Link CHG numbers for FP scanner cases so the next shift does not re-page
                  - Redact secrets before wide sharing; keep full evidence in the controlled ticket
                  - Portfolio habit matches exam/interview storytelling
                  - End with next action owners and due dates, not vibes

                Worked example:
                Good spray pack: source IP, distinct user count, success hunt result (none/found), block action + who approved, ticket link, detection tune note. Bad pack: disposition 'looks fine' with zero evidence.

                                More desk clues:
                  - Minimum pack: summary, timeline, sources, IOCs, actions, disposition, next owner.
                  - Include negative findings ("no successful 4624 from attacking IP").
                  - Link CHG numbers for FP scanner cases so the next shift does not re-page.
                  - Redact secrets before wide sharing; keep full evidence in the controlled ticket.

                How to answer on the exam:
                1. Write so the next shift can continue.
                  2. Separate facts from guesses.
                  3. End with next action owners.

                Common trap: disposition 'looks fine' with zero evidence attached. Near-miss: tool brand soup with no timeline or disposition.

                Remember: If it is not in the pack, it did not happen for the next analyst.
                """),
            ("Do the job", """
                Where you see this at work: interview prompt: walk me through your last true positive.

                In Security+ terms, that is using the pack as a talk-track.

                Talk-track: alert → source → contain → eradicate → recover → lessons. Point to artifacts.

                Technical specifics:
                - Keep customer data handling rules in mind for Boundry privacy
                  - Redact secrets in exported packs when sharing broadly
                  - Cite concrete IDs: 4625 aggregates, EDR alert ID, CHG number

                Worked example:
                Strong answer cites 4625 aggregates, the contain action, and the harden follow-up, not vibes. Weak answer lists vendor logos.

                How to answer on the exam:
                1. Structure the story on IR phases.
                  2. Cite sources.
                  3. Name the control that should prevent reprise.

                Common trap: tool brand soup with no timeline or disposition.

                Remember: Packs win handoffs, exams, and interviews.
                """),
        ],
        [
            _mc("Minimum handoff pack includes:",
                ["Only 'looks bad'", "Timeline, IOCs, sources, containment, disposition, next",
                 "Only meme", "Only open RDP"], 1,
                "Operable handoff."),
            _mc("IOC list for macro case should include:",
                ["File hash, sender, URLs, host, user", "Only wallpaper", "Only RPO", "Only CHG joke"], 0,
                "Actionable indicators."),
            _mc("Disposition FP without evidence note is:",
                ["Fine forever", "Weak: next analyst cannot learn why",
                 "Required", "A honeypot"], 1,
                "Explain FPs too."),
        ],
        [
            _qz("q_d4_15a", "Timeline purpose:",
                ["Order events for causality", "Open 3389", "Disable MFA", "Set VLAN paint"], 0,
                "Correct. Story order. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_15b", "Next steps field should be:",
                ["Empty", "Concrete ownerable actions", "Only blame", "Only jokes"], 1,
                "Correct. Drive closure. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_15c", "MITRE tagging helps later hunts by:",
                ["Naming techniques consistently", "Replacing logs", "Opening RDP", "Skipping IR"], 0,
                "Correct. Shared taxonomy. Common trap: answers that ignore containment, ownership, or the open path. "),
            _qz("q_d4_15d", "Portfolio cases train you for:",
                ["Interviews and real handoffs", "Only Domain 1 vocab quizzes",
                 "Only toner", "Only cold sites"], 0,
                "Correct. Career Lab loop. Common trap: answers that ignore containment, ownership, or the open path. "),
        ],
        job_ctas="d4",
    )
