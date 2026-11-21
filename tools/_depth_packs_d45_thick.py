"""Option 1 deepen: overwrite D4/D5 DEPTH packs to the D1 word bar.

Executed last by tools/_apply_option1_depth.py (body/put/DEPTH in globals).
Adds denser Technical specifics, worked examples, and tech near-miss traps.
Keeps work-facing picture + In Security+ terms bridge. No fluffy metaphors.
"""

# ---------------------------------------------------------------------------
# DOMAIN 4 (15)
# ---------------------------------------------------------------------------
put(
    "sp_d4_01_harden_compute",
    18,
    [
        (
            "What you touch on a ticket",
            body(
                orient=(
                    "Hardening means reducing attack surface on compute: operating systems, "
                    "virtual machines, containers, and golden images. Attack surface is every "
                    "service, account, and tool an attacker could abuse."
                ),
                work=(
                    "you remove local admin from HR laptops, enable EDR and ASR (attack surface "
                    "reduction) rules, patch, disable unused services, turn on PowerShell script "
                    "block logging on jump hosts, and confirm BitLocker on traveling devices."
                ),
                formal="compute hardening techniques used in day-to-day ops",
                beats=(
                    "Compute harden list:\n"
                    "  1. Patch / update on a measured cadence\n"
                    "  2. Remove unused roles, services, and listeners\n"
                    "  3. Least privilege: no standing local admin for daily work\n"
                    "  4. EDR healthy + ASR / application control where used\n"
                    "  5. Secure baseline (CIS-style or org GPO/Intune) + disk encryption\n"
                    "  6. Host firewall on; unnecessary ports closed"
                ),
                tech=(
                    "  - ASR example: block Office apps from creating child processes "
                    "(excel.exe → powershell.exe -enc is the classic fail)\n"
                    "  - Jump / PAM hosts: no email, no browsing, MFA, stricter audit "
                    "(4688 process create / PowerShell 4104 where enabled)\n"
                    "  - Containers: minimal base image, non-root, scanned in CI, no secrets "
                    "baked into layers\n"
                    "  - Verify after deploy: test that Office→script is blocked on a canary host\n"
                    "  - Drift: golden image Monday, HR laptop Friday with local admin again = "
                    "hardening failed\n"
                    "  - Disk encryption (BitLocker/FileVault) protects lost devices; it does not "
                    "stop a logged-in macro"
                ),
                worked=(
                    "Invoice.xlsm opens on WS-HR-03. Macros launch powershell.exe -enc. "
                    "EDR alerts. Which harden controls should already have been in place?\n"
                    "  - Prefer: ASR / macro block + least local admin + healthy EDR\n"
                    "  - Not enough alone: wallpaper policy, annual AUP click, prettier SIEM theme\n"
                    "  - After the fact: isolate (corrective). That is IR, not proof you hardened."
                ),
                how=(
                    "  1. Name the compute surface (laptop, jump host, container, VM).\n"
                    "  2. Pick the harden control that closes the path in the question.\n"
                    "  3. Prefer prevent (ASR, remove admin, patch) before detect-only answers.\n"
                    "  4. Ask whether the control was verified after deploy."
                ),
                trap=(
                    "answering 'install more wallpaper' or 'disable EDR to speed the PC.' "
                    "Another near-miss: calling BitLocker the fix for Office→script on an "
                    "unlocked session. BitLocker is at-rest. The path was execution."
                ),
                remember="Hardening removes paths before the alert fires. Verify it still holds after drift.",
            ),
        ),
        (
            "Do the job",
            body(
                work="PBQ-style match: each failure maps to one harden move you can name.",
                formal="applying hardening that matches the scenario",
                beats=(
                    "Quick fits:\n"
                    "  Macro→PS → ASR / block internet macros\n"
                    "  Standing local admin → remove / PAM\n"
                    "  Unpatched VPN client → patch or replace\n"
                    "  Cleartext laptop at rest → BitLocker\n"
                    "  Secrets in container image → rebuild + secret store"
                ),
                tech=(
                    "  - Change-control hardening pushes (CHG). Verify after deploy.\n"
                    "  - Exceptions need owner + compensating control + review date\n"
                    "  - Baseline tools: Intune/GPO/Ansible/image pipelines, not tribal memory"
                ),
                worked=(
                    "If excel→powershell still works after a 'hardening' ticket, you hardened "
                    "the wrong control or never verified. Reopen the ticket. Do not mark done."
                ),
                how=(
                    "  1. Match control to path.\n"
                    "  2. Verify the control actually applied.\n"
                    "  3. Keep exceptions owned."
                ),
                trap="claiming hardened when the original execution path still works on a test host.",
                remember="Verify hardening. Drift undoes baselines.",
            ),
        ),
    ],
)

put(
    "sp_d4_02_harden_network_app",
    17,
    [
        (
            "Close management paths",
            body(
                orient=(
                    "Network and application hardening closes remote-access and app-layer paths. "
                    "Management plane means admin protocols (RDP, SSH, vendor consoles)."
                ),
                work=(
                    "deny inbound TCP 3389 and TCP 22 from the internet, require MFA VPN or a "
                    "jump host, turn off unused HTTP verbs and sample pages, put TLS on admin "
                    "UIs, and rate-limit login endpoints that get sprayed."
                ),
                formal="network and application hardening in operations",
                beats=(
                    "Network/app harden:\n"
                    "  1. Management plane not on the open internet\n"
                    "  2. TLS on apps; no cleartext admin\n"
                    "  3. Remove default accounts, passwords, and sample pages\n"
                    "  4. Patch apps; input validation / secure headers where you own code\n"
                    "  5. API keys not in mobile apps, chat, or repos"
                ),
                tech=(
                    "  - Priority path: internet → TCP 3389/22 → domain controller or jump host "
                    "beats most CVE chatter until that ALLOW is gone\n"
                    "  - Brokered admin: VPN (UDP 500/4500 or TLS VPN) + PAM/jump + MFA\n"
                    "  - WAF helps HTTP classes (injection, some bot abuse). It does not close "
                    "non-HTTP management ports\n"
                    "  - Disable legacy app auth that bypasses MFA (basic auth, legacy SMTP/POP)\n"
                    "  - After removing 3389 ALLOW: confirm with rule review + external scan + "
                    "SIEM quiet on that path"
                ),
                worked=(
                    "Firewall shows ALLOW tcp/3389 from 0.0.0.0/0 to PROD-DC01. App team wants "
                    "a WAF purchase for a different web app the same week.\n"
                    "  - First harden: remove or broker that RDP path (network harden)\n"
                    "  - WAF may help the web app later; it is the wrong primary answer for RDP\n"
                    "  - Default /admin with vendor password on a public site is app hardening"
                ),
                how=(
                    "  1. Find the exposed service and protocol.\n"
                    "  2. Close or broker access before shopping new dashboards.\n"
                    "  3. Patch and remove defaults on what must stay exposed."
                ),
                trap=(
                    "WAF-only answer for a non-HTTP management port exposure. Another near-miss: "
                    "'we have SIEM' as a substitute for closing internet RDP."
                ),
                remember="Close management paths first. Then harden the app features you must expose.",
            ),
        ),
        (
            "App layer",
            body(
                work=(
                    "a public form reflects script tags; another app still has /admin with the "
                    "vendor default password; a repo has cloud keys in plaintext."
                ),
                formal="application security hygiene as ops hardening",
                beats=(
                    "App beats: patch, remove defaults, least-privilege DB accounts, secrets "
                    "management, rate-limit auth endpoints."
                ),
                tech=(
                    "  - Secrets in Git are an ops finding with rotate + purge history as needed\n"
                    "  - Rate limiting and lockout help password spray against login pages\n"
                    "  - TLS on the admin UI; HSTS where appropriate\n"
                    "  - Remove sample apps and debug endpoints from prod"
                ),
                worked=(
                    "Default creds on a public admin page are Domain 2 (exposure) and Domain 4 "
                    "(failed harden). Fix: remove defaults, force unique secrets, put admin off "
                    "the open internet if possible."
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
    18,
    [
        (
            "Why svc_backup2 at 03:14 is a crisis",
            body(
                orient=(
                    "Asset management means knowing what you have, who owns it, how sensitive it "
                    "is, and what privilege it holds. You cannot defend ghosts."
                ),
                work=(
                    "a new local admin svc_backup2 appears at 03:14 with no change ticket. "
                    "Inventory did not list that service account as approved. VPN objects and "
                    "SaaS admins were never in the CMDB either."
                ),
                formal="hardware, software, data, and account asset management with lifecycle hygiene",
                beats=(
                    "Asset beats:\n"
                    "  1. Inventory devices, apps, accounts, data stores, cloud roles\n"
                    "  2. Owner and classification for each critical asset\n"
                    "  3. Lifecycle: joiner / mover / leaver / decommission\n"
                    "  4. Remove ghost admins, stale VPN, orphaned API keys"
                ),
                tech=(
                    "  - Unexpected privileged account = integrity + asset control failure; "
                    "hunt 4720/4728-style creates and local admin group changes\n"
                    "  - Inventory must include service accounts, break-glass, VPN profiles, "
                    "and SaaS OAuth apps, not only laptops\n"
                    "  - Offboard day-0 checklist: disable account, revoke MFA devices, pull "
                    "groups, wipe/return device, kill tokens\n"
                    "  - Shadow IT appears where ownership and inventory are weak\n"
                    "  - Classification (public / internal / confidential) drives backup, DLP, "
                    "and who may admin"
                ),
                worked=(
                    "svc_backup2 at 03:14, no CHG, missing from inventory:\n"
                    "  - Escalate as unauthorized privilege, not 'backups need admin'\n"
                    "  - Contain: disable/reset, isolate if host-tied, hunt lateral use\n"
                    "  - Program fix: inventory + joiner/mover/leaver SLA so ghosts cannot hide"
                ),
                how=(
                    "  1. Ask if the asset or account should exist.\n"
                    "  2. Check owner and ticket.\n"
                    "  3. Prefer lifecycle answers for stale access."
                ),
                trap=(
                    "ignoring unknown admins because 'backups need admin.' Near-miss: only "
                    "counting laptops while privileged SaaS and VPN objects stay invisible."
                ),
                remember="You cannot defend assets you do not know you have.",
            ),
        ),
        (
            "Lifecycle",
            body(
                work="contractor laptop and VPN still active 60 days after offboarding.",
                formal="asset and identity lifecycle operations",
                beats=(
                    "Offboard checklist: account disable, MFA devices, VPN, groups, laptop "
                    "return/wipe, API tokens, shared mailbox access."
                ),
                tech=(
                    "  - Orphaned privileged service accounts are crown-jewel debt\n"
                    "  - CMDB / Intune / Entra accuracy is a control input, not paperwork vanity\n"
                    "  - Mover events (new role) need group changes the same week, not 'someday'"
                ),
                worked=(
                    "Stale contractor VPN is an asset/identity lifecycle miss and a remote vector. "
                    "Treat it like an open path: revoke, then find how long it stayed open."
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
    18,
    [
        (
            "Scan is not done",
            body(
                orient=(
                    "Vulnerability management is a lifecycle: discover, prioritize, remediate, "
                    "verify, then exception if needed. A scan file alone is not management."
                ),
                work=(
                    "Nessus finishes, tickets open with owners, teams patch or accept risk with "
                    "a date, then rescans prove closure. A medium CVE on PROD-DC01 can outrank "
                    "a critical on a lab printer."
                ),
                formal="vulnerability management lifecycle operations",
                beats=(
                    "Lifecycle:\n"
                    "  1. Discover (scan / agent / inventory / threat intel)\n"
                    "  2. Prioritize (severity + asset value + exploitability + path open)\n"
                    "  3. Remediate (patch / config fix / compensate)\n"
                    "  4. Verify (rescan or config proof)\n"
                    "  5. Exception with owner, compensating control, and review if needed"
                ),
                tech=(
                    "  - CVSS is an input, not a religion. Asset context can override color\n"
                    "  - Misconfigs without a CVE (open 3389, legacy auth) still enter the same loop\n"
                    "  - SLA examples teams use: critical internet-facing days, not months\n"
                    "  - Rescan is the verify step. Green ticket without rescan is incomplete\n"
                    "  - Exceptions need compensating control + owner + review date + approver\n"
                    "  - KEV / active exploit intel can jump a medium ahead of a quiet critical"
                ),
                worked=(
                    "Scan drops 200 findings. Analyst files zero tickets. Manager asks 'are we done?'\n"
                    "  - No. Discover without prioritize/remediate/verify is incomplete\n"
                    "  - Prioritize: DC + internet path first; lab printer later\n"
                    "  - Exception without expiry for internet RDP to DC is a governance failure, "
                    "not mature risk acceptance"
                ),
                how=(
                    "  1. Do not stop at 'scanned.'\n"
                    "  2. Prioritize by risk, not only by color.\n"
                    "  3. Verify closure with rescan or equivalent proof."
                ),
                trap=(
                    "closing criticals as 'accepted' with no owner, compensating control, or date. "
                    "Near-miss: treating CVSS 9 on an offline lab higher than CVSS 6 on a DC "
                    "with an open management path."
                ),
                remember="Vulnerability management ends at verified fix or owned exception.",
            ),
        ),
        (
            "Exceptions",
            body(
                work="legacy OT box cannot patch; you segment and monitor with a 90-day review.",
                formal="owned compensating exceptions inside vulnerability management",
                beats=(
                    "Exception needs: reason, compensating control, owner, review date, approver."
                ),
                tech=(
                    "  - Internet RDP to a DC should almost never clear exception review\n"
                    "  - Prefer architecture fix (segment, broker) over eternal paperwork\n"
                    "  - Tie exception IDs into SIEM suppressions so tuning stays honest"
                ),
                worked=(
                    "Documented segment + monitor for unpatchable OT can be valid. "
                    "Hallway yes for DC RDP is not. Write the compensating control or remove the path."
                ),
                how=(
                    "  1. Prefer remediate.\n"
                    "  2. If except, demand compensating control + date.\n"
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
    17,
    [
        (
            "Better findings",
            body(
                orient=(
                    "Scan context means knowing what you scanned, with what credentials, under "
                    "which change ticket, and whether the target can tolerate the scan."
                ),
                work=(
                    "JUMP-01 runs an authenticated Nessus scan under CHG-512. Separately, "
                    "internet noise hits the edge. Separately, someone almost scanned OT at noon "
                    "with aggressive plugins."
                ),
                formal="vulnerability scanning with authorization, scope, and safety",
                beats=(
                    "Context beats:\n"
                    "  1. Authorized scope + window (CHG)\n"
                    "  2. Credentialed vs uncredentialed tradeoffs\n"
                    "  3. Asset criticality in prioritization\n"
                    "  4. Safe methods for fragile / OT systems"
                ),
                tech=(
                    "  - Credentialed scans find missing patches and local issues better; protect "
                    "scanner credentials like tier-0 secrets\n"
                    "  - Match scanner host/IP in SIEM to CHG before paging APT on JUMP-01\n"
                    "  - Allow-list the scanner in firewall/SIEM exceptions in the same ticket\n"
                    "  - OT/ICS: vendor-approved or passive methods, stop conditions, off-peak\n"
                    "  - Uncredentialed edge scans still help find exposure; they are not a full inventory"
                ),
                worked=(
                    "SIEM fires on JUMP-01 port sweeps. Ticket shows CHG-512 authenticated scan:\n"
                    "  - Document as authorized activity; do not open a nation-state novel\n"
                    "  - Contrast: same ports from an unknown overseas IP with no CHG → investigate\n"
                    "  - Aggressive OT scan at noon without approval → stop, safety + change miss"
                ),
                how=(
                    "  1. Check authorization and scope.\n"
                    "  2. Use asset context in priority.\n"
                    "  3. Do not confuse scanner traffic with attackers without identity checks."
                ),
                trap=(
                    "escalating known scanner IPs with matching CHG as APT. Near-miss: skipping "
                    "credentialed scans forever because uncredentialed PDFs look green."
                ),
                remember="Scanner context saves shifts. Safety protects fragile systems.",
            ),
        ),
        (
            "Safety",
            body(
                work="someone runs a full aggressive scan against the plant network at noon.",
                formal="safe scanning practices",
                beats=(
                    "Safety: approve scope, rate limits, avoid peak on fragile hosts, stop on "
                    "adverse impact, document scanner allow-lists with the ticket."
                ),
                tech=(
                    "  - Production DC scans may still need change windows when disruptive\n"
                    "  - Record plugin sets and exclusions so results are repeatable\n"
                    "  - Adverse impact without a stop plan fails safety and change management"
                ),
                worked=(
                    "Plant scan knocks a PLC offline. No CHG, no stop plan. That is an ops miss "
                    "even if the intent was 'security.'"
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
                    "open SigninLogs or Windows 4625, check for 4624 success, check CHG, then "
                    "contain or mark false positive with notes."
                ),
                formal="alert triage workflow: prioritize, validate, escalate, document",
                beats=(
                    "Queue beats:\n"
                    "  1. Prioritize by severity + asset tier + path open + execution already?\n"
                    "  2. Validate true positive vs false positive / CHG\n"
                    "  3. Contain when needed\n"
                    "  4. Ticket with evidence\n"
                    "  5. Tune noisy rules with change control"
                ),
                tech=(
                    "  - Alert is not an incident until validated\n"
                    "  - Priority inputs: CRITICAL/HIGH labels, crown-jewel asset, open ALLOW, "
                    "EDR prevention failed\n"
                    "  - Live malware or BEC: contain before writing the novel\n"
                    "  - Correlation thresholds must match reality (scanner nights vs spray)\n"
                    "  - SOAR can enrich WHOIS, geo, ticket fields; humans gate destructive actions\n"
                    "  - Disposition language: TP / FP / benign-true (authorized scan) with CHG link"
                ),
                worked=(
                    "Two alerts in one hour:\n"
                    "  A) 30 distinct users failing from one IP, then one 4624 success\n"
                    "  B) JUMP-01 sweeps matching CHG-512\n"
                    "Treat A as likely spray: block/rate-limit, hunt success, ticket. "
                    "Treat B as authorized: document FP/benign with CHG. Same queue, different urgency."
                ),
                how=(
                    "  1. Read severity and asset.\n"
                    "  2. Validate with the right source in minutes.\n"
                    "  3. Act, then document."
                ),
                trap=(
                    "closing high-severity crown-jewel path alerts as noise because the queue is "
                    "long. Near-miss: identical handling for CHG scanners and real spray."
                ),
                remember="Work the queue by path and asset, not by who yelled last.",
            ),
        ),
        (
            "Boundry habit",
            body(
                work="alert → source → contain → ticket, in that order when execution or BEC is live.",
                formal="SOC operating rhythm for Domain 4",
                beats=(
                    "Habit: do not write a novel before containment when malware is running."
                ),
                tech=(
                    "  - Enrichment first is fine if it is seconds, not hours\n"
                    "  - Document enough for the next analyst: sources, IOCs, actions, disposition\n"
                    "  - Tune noise with CHG-linked exclusions; do not disable crown-jewel detections"
                ),
                worked=(
                    "Encoded PowerShell alert on finance laptop: isolate first, then hunt the "
                    "campaign hash in mail and EDR. Essay after containment."
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
    18,
    [
        (
            "Tool roles",
            body(
                orient=(
                    "SIEM aggregates and correlates logs across sources. EDR focuses on endpoints "
                    "(process trees, isolate). SOAR automates repeatable response steps. Know "
                    "which tool answers which question."
                ),
                work=(
                    "identity spray → SIEM plus SigninLogs. excel→powershell → EDR. auto-enrich "
                    "WHOIS and open ticket → SOAR. Firewall ALLOW hunt → firewall logs plus SIEM. "
                    "Mailbox forward → mailbox audit / unified audit log."
                ),
                formal="monitoring tool roles and when to use each",
                beats=(
                    "Tool map:\n"
                    "  SIEM: correlation, history, multi-source queries (SPL/KQL habits)\n"
                    "  EDR: process tree, isolate, host IOCs, hash hunt\n"
                    "  NDR/firewall/VPN: path ALLOW/DROP, remote access\n"
                    "  Identity logs: AuthN patterns (462x, SigninLogs)\n"
                    "  Mail tooling: rules, forwards, phishing delivery\n"
                    "  SOAR: automate enrich/notify/contain with guardrails"
                ),
                tech=(
                    "  - Identity pattern → SigninLogs / 4625 and 4624 / SIEM aggregate by src_ip\n"
                    "  - Execution chain → EDR parent/child + command line\n"
                    "  - Path open/blocked → firewall / VPN / NSG\n"
                    "  - Mailbox persistence → mailbox audit / UAL (New-InboxRule, forward)\n"
                    "  - Retention matters: 7-day keep may erase the BEC staging window\n"
                    "  - Wrong-tool answers are classic near-misses on the exam"
                ),
                worked=(
                    "Question asks for best place to confirm excel.exe launched powershell.exe -enc:\n"
                    "  - EDR process tree (or equivalent endpoint telemetry)\n"
                    "  - Not firewall alone, not AUP poster, not CVSS PDF\n"
                    "Contrast: 30-user failures from one IP → identity/SIEM aggregation first."
                ),
                how=(
                    "  1. Ask what evidence you need.\n"
                    "  2. Pick the tool that holds that evidence.\n"
                    "  3. Correlate across tools when the story spans planes."
                ),
                trap=(
                    "using only firewall logs for a mailbox forward BEC. Near-miss: naming a "
                    "vendor brand without saying which evidence pane you open."
                ),
                remember="Pick the tool that holds the evidence the question needs.",
            ),
        ),
        (
            "Do the job CTAs",
            body(
                work="Boundry CTAs: SPL Learn, KQL Learn, SOAR Lab, Shift Sim.",
                formal="practicing tool use as part of ops learning",
                beats=(
                    "Practice map: identity hunts in SPL/KQL, containment playbooks in SOAR, "
                    "queue reps in Shift Sim."
                ),
                tech=(
                    "  - Tool skill without triage judgment still fails interviews\n"
                    "  - Judgment without tool paths fails exams that ask for sources\n"
                    "  - NetFlow/proxy helps east-west and egress when EDR is thin"
                ),
                worked=(
                    "Interview line that works: I aggregate failures by source IP in the SIEM, "
                    "hunt success, then confirm host process trees in EDR before isolate."
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
    17,
    [
        (
            "Tune, don't just watch",
            body(
                orient=(
                    "Enhancing capabilities means tuning rules, adding detections, and closing "
                    "coverage gaps on purpose. Watching a noisy console is not the goal."
                ),
                work=(
                    "Failed Logon Burst is too noisy on scanner nights, so you exclude JUMP-01 "
                    "with CHG linkage and a time window. You add a detection for external forward "
                    "rule creation after a BEC. You re-test with a known true-positive case."
                ),
                formal="modifying enterprise detection and prevention capabilities with change discipline",
                beats=(
                    "Tune beats:\n"
                    "  1. Measure false positives and false negatives\n"
                    "  2. Narrow allow-lists carefully (host/identity/time)\n"
                    "  3. Add detections for missed techniques\n"
                    "  4. Change-control the tune\n"
                    "  5. Re-verify with test cases"
                ),
                tech=(
                    "  - Narrow exclusions (JUMP-01 + CHG window) beat excluding a whole /8 forever\n"
                    "  - Add detections from real incidents: external forward rules, Office→PS, "
                    "legacy auth success\n"
                    "  - Preventive tunes (ASR, Conditional Access) need stakeholder verify\n"
                    "  - Detection content is production: reason, review, rollback\n"
                    "  - Over-tuning that hides real spray creates false negatives (missed attacks)"
                ),
                worked=(
                    "Good tune: scanner identity exclusion documented in CHG-512, re-tested next window. "
                    "Bad tune: disable the spray rule because it is noisy. "
                    "After BEC: add forward-rule detection; do not only write a poster."
                ),
                how=(
                    "  1. Prefer narrow exceptions.\n"
                    "  2. Document and verify.\n"
                    "  3. Never 'fix' noise by turning off crown-jewel detections."
                ),
                trap=(
                    "disabling a noisy rule that also catches real spray. Near-miss: permanent "
                    "/8 allow-list 'so the dashboard looks green.'"
                ),
                remember="Tune with evidence and ownership. Do not blind yourself.",
            ),
        ),
        (
            "Change discipline",
            body(
                work="someone edits a SIEM rule in prod with no ticket and no peer review.",
                formal="change management applied to detection content",
                beats=(
                    "Detection changes need: reason, peer review when possible, rollback, test."
                ),
                tech=(
                    "  - Version detections when you can (git or platform history)\n"
                    "  - Break-glass urgent blocks still get an after-action ticket\n"
                    "  - Re-test with a known true-positive case after tuning"
                ),
                worked=(
                    "Undocumented rule edit that drops 3389 alerts is an ops failure even if "
                    "meant well. Restore, ticket, peer review."
                ),
                how=(
                    "  1. Demand ticket and reason.\n"
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
    18,
    [
        (
            "Daily IAM, not slides",
            body(
                orient=(
                    "IAM operations means running identity day to day: joiners, movers, leavers, "
                    "MFA, roles, and access reviews. Identity is often the real perimeter."
                ),
                work=(
                    "disable accounts on termination day, require MFA for remote admin, review "
                    "Entra privileged roles monthly, kill legacy auth that skips prompts, and "
                    "keep break-glass accounts monitored and rarely used."
                ),
                formal="identity and access management operations",
                beats=(
                    "IAM ops map:\n"
                    "  1. Provision / deprovision promptly (SLA, not heroes)\n"
                    "  2. MFA and Conditional Access\n"
                    "  3. Least privilege / JIT (just-in-time) where possible\n"
                    "  4. Access reviews on privileged roles\n"
                    "  5. Service account hygiene (no interactive daily-driver DA)"
                ),
                tech=(
                    "  - Standing Global Admin / Domain Admin for daily mail is an ops failure\n"
                    "  - Disable legacy auth; monitor for breakage with a backout plan\n"
                    "  - Joiner/mover/leaver SLAs beat quarterly cleanup heroes\n"
                    "  - Break-glass: long random secrets, monitored, alert on use, offline procedure\n"
                    "  - After BEC: revoke sessions/refresh tokens, reset, review mailbox permissions "
                    "and privileged group adds (4728/Directory Audit)"
                ),
                worked=(
                    "CFO mailbox compromised via legacy auth. Contain: revoke sessions, reset, "
                    "kill malicious forward. IAM ops follow-up: disable legacy auth org-wide with "
                    "monitoring, Conditional Access harden, privileged role review. Poster-only fails."
                ),
                how=(
                    "  1. Look for lifecycle and privilege clues.\n"
                    "  2. Prefer least privilege + MFA answers.\n"
                    "  3. Keep AuthN (prove who) vs AuthZ (what they may do) separate when asked."
                ),
                trap=(
                    "shared admin passwords in a spreadsheet as 'ops pragmatism.' Near-miss: "
                    "quarterly access review theater while leavers stay enabled for weeks."
                ),
                remember="IAM ops closes the paths Domain 2 keeps exploiting.",
            ),
        ),
        (
            "Privilege",
            body(
                work=(
                    "domain admin used for daily email. Service account has interactive logon "
                    "and admin everywhere."
                ),
                formal="privileged access operations",
                beats=(
                    "Privilege beats: separate admin accounts, PAM/JIT, no daily email on DA, "
                    "monitor privileged groups, tier admin paths."
                ),
                tech=(
                    "  - Monitor 4672 / privileged logon and directory group changes\n"
                    "  - Tiered admin ideas: user workstation vs server vs DC admin separation\n"
                    "  - PIM / JIT eligible roles beat standing Owner everywhere"
                ),
                worked=(
                    "Daily-driver domain admin is an IAM ops failure waiting for phishing. "
                    "Split accounts: mail on standard user, admin on separate MFA-protected admin ID."
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
    18,
    [
        (
            "Automate the repeatable",
            body(
                orient=(
                    "SOAR means security orchestration, automation, and response. It stitches "
                    "tools together and automates repeatable steps. Humans still approve "
                    "destructive actions when confidence or impact is high."
                ),
                work=(
                    "playbook auto-enriches spray IPs, opens a ticket with standard fields, and "
                    "suggests a firewall block. A human clicks approve before the change. High-"
                    "confidence EDR isolate may auto-run with guardrails and audit logs."
                ),
                formal="automation and orchestration with human gates",
                beats=(
                    "SOAR beats:\n"
                    "  1. Automate enrich / notify / ticket first\n"
                    "  2. Gate high-impact contain (disable user, wide block, mass isolate)\n"
                    "  3. Measure time saved and error rate\n"
                    "  4. Keep playbooks under change control\n"
                    "  5. Idempotent steps + rate limits + kill switch"
                ),
                tech=(
                    "  - Bad automation: auto-disable VIP accounts on every travel false positive\n"
                    "  - Good automation: enrich + consistent ticket fields + optional contain\n"
                    "  - Log every automated action for IR timelines and audit\n"
                    "  - Map playbooks to IR phases (enrich in analysis, isolate in containment)\n"
                    "  - Confidence thresholds and allow-lists prevent ticket storms"
                ),
                worked=(
                    "Auto-block every foreign MFA success without context creates availability "
                    "outages for travelers. Better: enrich geo/device/MFA detail, open ticket, "
                    "human approve block when spray/BEC pattern matches. "
                    "Runaway playbook opening 200 duplicate tickets is itself an incident."
                ),
                how=(
                    "  1. Automate toil first.\n"
                    "  2. Gate destructive steps.\n"
                    "  3. Prefer consistent evidence packs and audit logs."
                ),
                trap=(
                    "fully automatic account wipe on every anomaly with no confidence check. "
                    "Near-miss: SOAR as an excuse to remove analysts on day one."
                ),
                remember="Automate the repeatable. Gate the irreversible.",
            ),
        ),
        (
            "Failure mode",
            body(
                work="playbook loops and opens 200 duplicate tickets overnight.",
                formal="safe automation design and failure handling",
                beats=(
                    "Failure beats: idempotency, rate limits, dead-letter handling, kill switch "
                    "for playbooks, staging tests when possible."
                ),
                tech=(
                    "  - Monitor automation like a production app (error rate, loop detection)\n"
                    "  - Rollback path for bad blocks/disables\n"
                    "  - Keep humans in the loop for crown-jewel identity actions"
                ),
                worked=(
                    "A runaway playbook is an availability and trust incident inside the SOC. "
                    "Kill switch, fix the loop, after-action with change control."
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
                    "sequences commonly include preparation, detection and analysis, containment, "
                    "eradication, recovery, and lessons learned."
                ),
                work=(
                    "malware on HR PC: detect in EDR, contain by isolate, eradicate persistence "
                    "and malicious mail rules, recover to known-good image with monitoring, then "
                    "lessons learned that add ASR and fix the mail path."
                ),
                formal="IR phase order and what belongs in each phase",
                beats=(
                    "Phase map:\n"
                    "  1. Preparation (before the fire): playbooks, contacts, tooling, authority\n"
                    "  2. Detection and analysis\n"
                    "  3. Containment (stop spread)\n"
                    "  4. Eradication (remove cause)\n"
                    "  5. Recovery (restore safely)\n"
                    "  6. Lessons learned / post-incident"
                ),
                tech=(
                    "  - Containment examples: isolate host, revoke sessions/tokens, block hash/IP, "
                    "disable malicious inbox rule, sinkhole domain\n"
                    "  - Eradication examples: remove persistence, disable legacy auth, delete "
                    "malware, reset credentials, patch the entry hole\n"
                    "  - Recovery examples: reimage, restore from known-good backup, re-enable "
                    "with heightened monitoring, validate RTO targets if business services\n"
                    "  - Contain before deep forensics when spread is active\n"
                    "  - Preparation failures show up as missing isolate authority or dead tooling"
                ),
                worked=(
                    "Live ransomware encrypting a finance share:\n"
                    "  - Wrong: leave host online overnight to 'analyze,' or jump to lessons-learned posters\n"
                    "  - Right order: detect/analyze enough to act → contain (isolate, revoke, block) "
                    "→ eradicate → recover → lessons learned (ASR, backup immutability, path fix)\n"
                    "BEC with active forward: contain the mailbox path before writing the novel."
                ),
                how=(
                    "  1. Identify the phase the question asks for.\n"
                    "  2. Do not jump to lessons learned before contain.\n"
                    "  3. Preparation answers only when the story is before the incident."
                ),
                trap=(
                    "recovery before containment, or lessons-learned posters as the first response "
                    "to live BEC. Near-miss: calling detection 'preparation' because dashboards look ready."
                ),
                remember="Detect → contain → eradicate → recover → learn. Prep before all of it.",
            ),
        ),
        (
            "Preparation",
            body(
                work="no call tree, no isolate authority, EDR licenses expired.",
                formal="preparation as the phase that makes the other phases possible",
                beats=(
                    "Prep checklist: roles, playbooks, tooling health, evidence handling, "
                    "management buy-in, tabletop exercises, legal/comms contacts."
                ),
                tech=(
                    "  - Tabletop exercises are preparation (people/decision gaps)\n"
                    "  - Break-glass and isolate authority must exist before 02:00\n"
                    "  - Tooling health: EDR agents reporting, SIEM ingest, backup restore tested"
                ),
                worked=(
                    "If analysts cannot isolate without a three-day debate, preparation failed. "
                    "Fix authority and tooling before the next fire."
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
    17,
    [
        (
            "Who needs to know",
            body(
                orient=(
                    "IR communications and documentation keep the right people informed without "
                    "leaking chaos or secrets. The ticket is the single source of truth."
                ),
                work=(
                    "finance and legal need BEC payment-risk heads-up early. Executives get clear "
                    "status, not raw malware samples in email. Users get safety notices on approved "
                    "channels. The ticket holds timeline, actions, and IOCs."
                ),
                formal="incident communications, escalation paths, and evidence documentation",
                beats=(
                    "Comms beats:\n"
                    "  1. Need-to-know + role-based updates\n"
                    "  2. Single source of truth ticket\n"
                    "  3. Preserve evidence / chain-of-custody ideas\n"
                    "  4. External comms via approved spokespeople when required"
                ),
                tech=(
                    "  - Audience map: finance for payment risk, legal/leadership for material "
                    "incidents, users for safety notices via approved channels\n"
                    "  - Ticket timeline fields: detect time, contain time, eradicate time, recover time\n"
                    "  - Do not paste live malware or secrets into open chat\n"
                    "  - Preserve EDR exports/hashes before casual reimage when analysis still matters\n"
                    "  - Regulatory notice may overlap Domain 5; escalate up when clocks start"
                ),
                worked=(
                    "BEC with invoice-change language in drafts:\n"
                    "  - Tell finance early about payment risk (do not wait for a perfect report)\n"
                    "  - Document revoke sessions, rule removal, IOCs in the ticket\n"
                    "  - Wrong: public social posts mid-incident, or zero notes so nobody can learn"
                ),
                how=(
                    "  1. Match audience to message.\n"
                    "  2. Document actions as you go.\n"
                    "  3. Preserve evidence before cleanup when feasible."
                ),
                trap=(
                    "public social posts mid-incident, or zero documentation so nobody can learn. "
                    "Near-miss: emailing live malware samples to a wide DL."
                ),
                remember="Right people, clear timeline, preserved evidence.",
            ),
        ),
        (
            "Evidence",
            body(
                work=(
                    "someone reimages WS-HR-03 before EDR export or memory capture when the "
                    "malware family is unknown."
                ),
                formal="basic evidence handling inside IR docs",
                beats=(
                    "Evidence beats: collect important artifacts first when safe, note who did "
                    "what when, avoid altering unnecessarily, hash samples."
                ),
                tech=(
                    "  - EDR timeline export into the ticket\n"
                    "  - Hash samples; do not email live malware broadly\n"
                    "  - Balance contain vs preserve: isolate can come first; capture before wipe when possible"
                ),
                worked=(
                    "Reimage may be right for recovery after capture. Capture-first when analysis "
                    "still matters. Write the decision if you had to wipe to stop spread."
                ),
                how=(
                    "  1. Balance contain vs preserve.\n"
                    "  2. Document decisions.\n"
                    "  3. Keep IOCs shareable safely (hashes, URLs, users)."
                ),
                trap="destroying the only evidence to 'be fast' without noting why.",
                remember="Write down what you did. Future you is a stakeholder.",
            ),
        ),
    ],
)

put(
    "sp_d4_13_sources_identity",
    18,
    [
        (
            "Build the evidence pack",
            body(
                orient=(
                    "Data sources for investigations must match the question. Identity sources "
                    "explain authentication and authorization stories (who signed in, what changed)."
                ),
                work=(
                    "spray: 4625/SigninLogs aggregates by source IP. BEC: mailbox audit plus "
                    "SigninLogs. Travel: SigninLogs plus HR note. Privileged add: directory audit "
                    "or 4728/4720-style clues. Always write the time window and timezone."
                ),
                formal="identity investigation sources and what each proves",
                beats=(
                    "Identity sources:\n"
                    "  Windows Security: 4624 success, 4625 failure, 4672 privilege, 4720/4728 group/user\n"
                    "  Entra SigninLogs / AuditLogs\n"
                    "  Mailbox audit / UAL for rules and forwards\n"
                    "  VPN auth logs\n"
                    "  Ticket / HR context for movers and travel"
                ),
                tech=(
                    "  - Spray hunt: failures by IP + distinct users, then hunt 4624/success\n"
                    "  - BEC: New-InboxRule / Set-Mailbox forwarding + client app / legacy flags\n"
                    "  - Privilege: directory audit for group adds / new admin users\n"
                    "  - Time bounds and clock skew: note UTC vs local in the ticket\n"
                    "  - Export rows into the ticket; do not only keep a blurry screenshot forever\n"
                    "  - Retention limits may force earlier legal-hold escalation"
                ),
                worked=(
                    "30 users failing from one IP → SigninLogs/SIEM identity sources, then success hunt. "
                    "Inbox forward rule → mailbox audit / UAL, not pfirewall alone. "
                    "Too-narrow 'last 5 minutes' window on a multi-day BEC misses staging."
                ),
                how=(
                    "  1. Name the activity type.\n"
                    "  2. Pick the source that records it.\n"
                    "  3. Bound time and account on purpose."
                ),
                trap=(
                    "firewall PCAP as the primary source for an inbox forward question. Near-miss: "
                    "deleting logs mid-investigation to 'reduce noise.'"
                ),
                remember="Identity stories need identity sources.",
            ),
        ),
        (
            "Time bounds",
            body(
                work=(
                    "you pull 'last 5 minutes' for a BEC that may have started days ago with legacy auth."
                ),
                formal="scoping investigation windows",
                beats=(
                    "Scope: first suspicious signal backward and forward; include rule creation "
                    "time and prior successes."
                ),
                tech=(
                    "  - Anchor on first IOC, then expand to related accounts and hosts\n"
                    "  - Note UTC vs local; write the window in the ticket\n"
                    "  - Retention may force earlier escalation for legal hold"
                ),
                worked=(
                    "Too-narrow windows miss staging. Too-wide windows drown you. Start from IOC "
                    "time and expand with a written bound."
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
    18,
    [
        (
            "Endpoint pack",
            body(
                orient=(
                    "Endpoint and network sources complete the investigation pack when hosts and "
                    "paths matter. Endpoint tells you what ran. Network tells you where it talked."
                ),
                work=(
                    "EDR process tree for excel→powershell, DNS/proxy for egress domains, firewall "
                    "for ALLOW/DROP on 3389/22/445, NetFlow for east-west after phishing, email "
                    "gateway for lure delivery."
                ),
                formal="endpoint and network data sources for investigations",
                beats=(
                    "Source map:\n"
                    "  EDR/syslog process: execution chain\n"
                    "  Firewall/VPN/NSG: path open/used/blocked\n"
                    "  DNS/proxy: callback domains\n"
                    "  Email gateway: lure delivery\n"
                    "  Disk/memory forensics when deeper analysis needed"
                ),
                tech=(
                    "  - Endpoint pack fields: parent/child, command line, hash, user, path, egress\n"
                    "  - Network pack fields: ALLOW/DROP, src/dst/port, VPN user mapping, DNS query\n"
                    "  - Pair beaconing domains with the host that owns the socket\n"
                    "  - If EDR is missing on a crown jewel, say the blind spot; lean on identity/network\n"
                    "  - Never open more inbound management ports to 'investigate live'\n"
                    "  - Syslog/HEC forwarder health is part of source reliability"
                ),
                worked=(
                    "Malware execution: EDR first (parent/child + hash). "
                    "Internet RDP exposure: firewall rules + auth attempts (462x). "
                    "Beaconing: proxy/DNS + EDR together. "
                    "ALLOW 3389 with no EDR on the DC means you are partly blind; say so and isolate faster."
                ),
                how=(
                    "  1. Match source to artifact.\n"
                    "  2. Corroborate across planes.\n"
                    "  3. Keep containment priority."
                ),
                trap=(
                    "network-only conclusions for a clear endpoint parent/child chain. Near-miss: "
                    "pretending coverage exists when the agent is missing."
                ),
                remember="Endpoint tells you what ran. Network tells you where it talked.",
            ),
        ),
        (
            "Network pack",
            body(
                work="ALLOW 3389 row plus no EDR on the DC means you are partly blind.",
                formal="recognizing coverage gaps as part of source selection",
                beats=(
                    "If a source is missing, say the gap, compensate with adjacent logs, and open "
                    "a coverage ticket after containment."
                ),
                tech=(
                    "  - Blind spots are Domain 4 findings too\n"
                    "  - Forwarder health and retention affect what you can prove later\n"
                    "  - VPN logs map remote user to source IP when edge logs only show the concentrator"
                ),
                worked=(
                    "No EDR on a crown jewel forces heavier network/identity reliance and faster "
                    "isolation decisions. Document the gap; do not invent process trees."
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
    18,
    [
        (
            "What good looks like",
            body(
                orient=(
                    "An investigation pack is the evidence bundle another analyst or manager can "
                    "reuse without a hallway conversation."
                ),
                work=(
                    "ticket with What / Why / Disposition / technique notes / IOCs / actions / "
                    "next steps. Exported log rows plus screenshots. Clear TP vs FP reason with "
                    "CHG links for scanner cases."
                ),
                formal="building a complete investigation documentation pack",
                beats=(
                    "Pack contents:\n"
                    "  1. Summary in plain English\n"
                    "  2. Timeline (detect / contain / eradicate / recover)\n"
                    "  3. Sources consulted\n"
                    "  4. IOCs (hashes, IPs, users, rules)\n"
                    "  5. Actions taken + who/when\n"
                    "  6. Disposition and follow-up (tune, patch, harden, owner)"
                ),
                tech=(
                    "  - Include negative findings ('no successful 4624 from attacking IP')\n"
                    "  - Link CHG numbers for FP scanner cases so the next shift does not re-page\n"
                    "  - Redact secrets before wide sharing; keep full evidence in the controlled ticket\n"
                    "  - Portfolio habit matches exam/interview storytelling\n"
                    "  - End with next action owners and due dates, not vibes"
                ),
                worked=(
                    "Good spray pack: source IP, distinct user count, success hunt result (none/found), "
                    "block action + who approved, ticket link, detection tune note. "
                    "Bad pack: disposition 'looks fine' with zero evidence."
                ),
                how=(
                    "  1. Write so the next shift can continue.\n"
                    "  2. Separate facts from guesses.\n"
                    "  3. End with next action owners."
                ),
                trap=(
                    "disposition 'looks fine' with zero evidence attached. Near-miss: tool brand "
                    "soup with no timeline or disposition."
                ),
                remember="If it is not in the pack, it did not happen for the next analyst.",
            ),
        ),
        (
            "Do the job",
            body(
                work="interview prompt: walk me through your last true positive.",
                formal="using the pack as a talk-track",
                beats=(
                    "Talk-track: alert → source → contain → eradicate → recover → lessons. "
                    "Point to artifacts."
                ),
                tech=(
                    "  - Keep customer data handling rules in mind for Boundry privacy\n"
                    "  - Redact secrets in exported packs when sharing broadly\n"
                    "  - Cite concrete IDs: 4625 aggregates, EDR alert ID, CHG number"
                ),
                worked=(
                    "Strong answer cites 4625 aggregates, the contain action, and the harden "
                    "follow-up, not vibes. Weak answer lists vendor logos."
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
# DOMAIN 5 (11)
# ---------------------------------------------------------------------------
put(
    "sp_d5_01_governance_policy",
    18,
    [
        (
            "Policy stack",
            body(
                orient=(
                    "Governance is how leadership directs and controls security. Policies state "
                    "management intent. Standards give mandatory specifics. Procedures tell "
                    "operators how to execute. Guidelines recommend softer practice."
                ),
                work=(
                    "AUP says do not bypass controls. Standard says MFA required for remote admin. "
                    "Procedure lists isolate-host steps. AUP alone does not stop Invoice.xlsm. "
                    "Policy bans internet RDP but the firewall still shows ALLOW."
                ),
                formal="policy vs standard vs procedure in a working governance stack",
                beats=(
                    "Stack:\n"
                    "  Policy → intent (AUP, information security policy)\n"
                    "  Standard → mandatory specifics (MFA for remote admin; no internet RDP to DCs)\n"
                    "  Procedure → runnable steps (isolate, restore, offboard)\n"
                    "  Guidelines → recommended, more flexible"
                ),
                tech=(
                    "  - Say/do test: policy text vs live Entra / firewall / EDR config\n"
                    "  - AUP without standards/procedures cannot stop macros alone\n"
                    "  - Ownership and review cadence keep documents from rotting\n"
                    "  - Exceptions must reference the standard they waive\n"
                    "  - Effective governance shows in enforced controls, not binders\n"
                    "  - Directive controls (Domain 1) often live in this stack"
                ),
                worked=(
                    "AUP is a directive policy. "
                    "Policy says no internet RDP but ALLOW tcp/3389 to PROD-DC01 exists:\n"
                    "  - Governance failure: not enforced, or uncontrolled exception\n"
                    "  - Fix: remove path or written exception with owner/date/compensating control "
                    "plus standard update. A signed PDF alone is not enforcement."
                ),
                how=(
                    "  1. Identify which document layer the question names.\n"
                    "  2. Prefer enforceability answers (controls match intent).\n"
                    "  3. Purpose first, product second."
                ),
                trap=(
                    "picking a brand-name tool before naming the governance purpose. Near-miss: "
                    "assuming a signed PDF equals enforcement."
                ),
                remember="Documents mean something only when controls match written intent.",
            ),
        ),
        (
            "Effective governance",
            body(
                work="legacy auth banned in policy but still enabled in Entra.",
                formal="say/do gap as a governance finding",
                beats=(
                    "Effectiveness checks: ownership, review cadence, enforcement evidence, "
                    "exception process."
                ),
                tech=(
                    "  - Unowned policies rot\n"
                    "  - Auditors look for say/do alignment\n"
                    "  - Export CA/legacy-auth config as evidence, not screenshots of a binder"
                ),
                worked=(
                    "Governance effectiveness shows in controls matching written intent. "
                    "Disable legacy auth, evidence SigninLogs policy, assign owner."
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
    17,
    [
        (
            "Who decides",
            body(
                orient=(
                    "Roles and responsibilities clarify who owns data, systems, approvals, and "
                    "exceptions. RACI is a common vocabulary: Responsible, Accountable, Consulted, Informed."
                ),
                work=(
                    "everyone thought someone else disabled legacy auth. Vendor RDP was approved "
                    "in a hallway. Nobody owned the review date. SOC can recommend; the system "
                    "owner accepts residual risk."
                ),
                formal="RACI-style clarity, data/system owners, and controlled exceptions",
                beats=(
                    "Role map:\n"
                    "  Data owner / system owner / security lead / SOC / IT ops\n"
                    "  RACI prevents 'I thought you did it'\n"
                    "  Exceptions: written approval, compensating control, owner, review date"
                ),
                tech=(
                    "  - Exception record fields: what, why, compensating control, approver, owner, expiry\n"
                    "  - Verbal 'vendor needs it' with no expiry is how ALLOW 3389 lives forever\n"
                    "  - Security committee / CAB for high-risk changes\n"
                    "  - High-risk paths (internet RDP to DC) should rarely clear exception review\n"
                    "  - RACI fails when Accountable is 'TBD' or 'the cloud'"
                ),
                worked=(
                    "Exception needs owner + compensating control + date. Hallway yes is not an "
                    "exception process. "
                    "If no Accountable name exists for prod DC firewall changes, governance is broken."
                ),
                how=(
                    "  1. Find who owns the decision.\n"
                    "  2. Prefer documented exception answers.\n"
                    "  3. Reject infinite silent risk."
                ),
                trap=(
                    "SOC 'accepting' residual risk for the business with no owner. Near-miss: "
                    "pretty RACI diagrams with no human names."
                ),
                remember="Exceptions without owners are just future incidents with paperwork missing.",
            ),
        ),
        (
            "RACI in practice",
            body(
                work="who is Responsible vs Accountable for disabling legacy auth?",
                formal="using RACI vocabulary without drowning in corporate theater",
                beats=(
                    "Accountable owns the outcome. Responsible does the work. Consulted/informed as needed."
                ),
                tech=(
                    "  - Exam may not require perfect RACI charts; it requires clear ownership\n"
                    "  - Name a human, not 'the cloud'\n"
                    "  - SOC executes contain; owners accept residual after eradicate"
                ),
                worked=(
                    "IT ops may be Responsible for the Entra toggle. CISO or system owner is "
                    "Accountable for residual identity risk. Write both names."
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
    18,
    [
        (
            "Risk process basics",
            body(
                orient=(
                    "Risk is the combination of likelihood and impact for a threat exploiting a "
                    "vulnerability against an asset. Risk management is identifying, analyzing, "
                    "evaluating, treating, and monitoring that risk."
                ),
                work=(
                    "open RDP to a DC is high impact. Commodity DROP noise on TCP 445 with no path "
                    "is lower. You identify, analyze likelihood × impact, compare to appetite, then treat."
                ),
                formal="risk identification and analysis ahead of treatment",
                beats=(
                    "Process beats:\n"
                    "  1. Identify assets / threats / vulnerabilities\n"
                    "  2. Analyze likelihood × impact (qualitative or quantitative)\n"
                    "  3. Evaluate against appetite / tolerance\n"
                    "  4. Treat (next lesson)\n"
                    "  5. Monitor and review"
                ),
                tech=(
                    "  - Inherent risk is before controls; residual risk remains after controls\n"
                    "  - Qualitative ratings (high/medium/low) are fine on Security+ if reasoned\n"
                    "  - Risk register tracks owner, rating, treatment, dates, residual\n"
                    "  - Appetite is leadership's band; analysts escalate facts that exceed it\n"
                    "  - SOC leftovers (open path, aged exception) should feed the register"
                ),
                worked=(
                    "NordVPN kill switch OFF with no owner:\n"
                    "  - Identify: tunnel drop could expose traffic/path assumptions\n"
                    "  - Analyze: impact depends on what was trusted to the VPN state\n"
                    "  - Evaluate vs appetite → treat (turn ON) or formally accept with owner/date\n"
                    "Do not skip analysis because a scanner is red elsewhere."
                ),
                how=(
                    "  1. Name asset + threat + weakness.\n"
                    "  2. Rough likelihood/impact.\n"
                    "  3. Do not skip to random tools before analysis."
                ),
                trap=(
                    "treating all risks as equal or skipping analysis because a scanner is red. "
                    "Near-miss: analyst silently 'accepting' DC RDP because the queue is busy."
                ),
                remember="Risk process: identify → analyze → treat → monitor.",
            ),
        ),
        (
            "Appetite and register",
            body(
                work="leadership accepts some low risks; crown-jewel RDP exposure is outside appetite.",
                formal="risk appetite/tolerance and the risk register as governance tools",
                beats=(
                    "Register fields that matter: risk, owner, rating, treatment, dates, residual."
                ),
                tech=(
                    "  - SOC findings should feed the register when residual risk remains\n"
                    "  - Appetite is leadership's call; analysts escalate facts\n"
                    "  - Review dates keep accepted risks from becoming forgotten culture"
                ),
                worked=(
                    "Analysts escalate evidence. Owners accept residual risk inside appetite. "
                    "Crown-jewel internet RDP should not hide as an undocumented shrug."
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
    18,
    [
        (
            "Treat the risk",
            body(
                orient=(
                    "Risk treatment choices are mitigate (reduce), accept, transfer "
                    "(insurance/contract), or avoid (stop the activity). Sometimes called risk response."
                ),
                work=(
                    "mitigate by turning kill switch ON, disabling legacy auth, removing 3389. "
                    "Accept a low lab risk with owner and date. Transfer some cyber residual via "
                    "insurance. Avoid by not offering internet RDP to identity stores at all."
                ),
                formal="risk treatment options and when each fits",
                beats=(
                    "Treatment map:\n"
                    "  Mitigate / reduce → controls that lower likelihood or impact\n"
                    "  Accept → informed, owned, documented\n"
                    "  Transfer → share residual (insurance, contract). Not a magic delete\n"
                    "  Avoid → stop doing the risky thing"
                ),
                tech=(
                    "  - Mitigate examples: kill switch ON, disable legacy auth, remove 3389, ASR on\n"
                    "  - Accept examples: low lab risk with owner/date; never silent DC exposure\n"
                    "  - Transfer examples: insurance/contracts still need operational controls\n"
                    "  - Avoid examples: do not offer internet RDP to DCs\n"
                    "  - Compensating controls are mitigation when the preferred control is blocked\n"
                    "  - Acceptance without owner/date is denial"
                ),
                worked=(
                    "Open internet RDP to DC: avoid/mitigate (remove path), not quiet accept. "
                    "Insurance without MFA is not responsible transfer theater. "
                    "After MFA and legacy auth off, some phishing residual remains; owner tracks it "
                    "with a review date (mature residual acceptance)."
                ),
                how=(
                    "  1. Match treatment to appetite and asset.\n"
                    "  2. Demand owner/date for accept.\n"
                    "  3. Prefer path removal for crown jewels."
                ),
                trap=(
                    "calling undocumented exposure 'accepted risk.' Near-miss: 'we mitigated, so "
                    "risk is zero forever.'"
                ),
                remember="Treatments need owners. Acceptance is a decision, not a shrug.",
            ),
        ),
        (
            "Residual risk",
            body(
                work="after MFA and legacy auth off, some phishing residual remains; owner tracks it.",
                formal="residual risk after controls",
                beats=(
                    "Always ask: what residual remains, who owns it, when reviewed?"
                ),
                tech=(
                    "  - Residual can be low but never mythical zero for human systems\n"
                    "  - Feed residual into awareness and detection tunes\n"
                    "  - Register status should show residual rating after treatment"
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
    18,
    [
        (
            "Vendors are in your blast radius",
            body(
                orient=(
                    "Third-party risk covers vendors, MSPs, SaaS, and supply-chain partners who "
                    "can hurt you through access, data, or updates."
                ),
                work=(
                    "mail filter vendor questionnaire before buy, MSP standing admin review, "
                    "SaaS holding customer data, and a compromised updater story. Offboard means "
                    "keys, apps, groups, SSO, and shared mailboxes, not only a goodbye email."
                ),
                formal="third-party risk assessment and ongoing management",
                beats=(
                    "Third-party beats:\n"
                    "  1. Due diligence before buy (questionnaires, SOC reports, security review)\n"
                    "  2. Contracts: security clauses, breach notice, data handling\n"
                    "  3. Least privilege integration\n"
                    "  4. Continuous monitoring / access reviews\n"
                    "  5. Offboard vendors fully"
                ),
                tech=(
                    "  - Tier vendors by data sensitivity and standing access depth\n"
                    "  - Standing domain admin for MSP without review = supply-chain style risk\n"
                    "  - Review MSP/VPN/admin accounts on a calendar, not only at purchase\n"
                    "  - Shared responsibility does not vanish because SaaS is pretty\n"
                    "  - Their breach notice clause matters when their incident becomes yours\n"
                    "  - Right to audit / evidence requests vary by contract"
                ),
                worked=(
                    "Vendor questionnaire before buying a mail filter = managerial third-party review. "
                    "MSP forever-admin without review = unmanaged third-party risk. "
                    "Pilot SaaS with ten unused admin accounts last year = lifecycle failure; revoke."
                ),
                how=(
                    "  1. Ask what data/access the third party has.\n"
                    "  2. Prefer least privilege + review answers.\n"
                    "  3. Include offboarding."
                ),
                trap=(
                    "trusting logos instead of access reviews. Near-miss: one-time questionnaire forever."
                ),
                remember="Third parties inherit your blast radius. Review them like it.",
            ),
        ),
        (
            "Ongoing management",
            body(
                work="SaaS app still has ten unused admin accounts from a pilot last year.",
                formal="continuous third-party access hygiene",
                beats=(
                    "Ongoing: inventory integrations, review admins, monitor alerts, renew "
                    "diligence on tier-1 vendors."
                ),
                tech=(
                    "  - Tier vendors by data sensitivity / access depth\n"
                    "  - Incident clauses matter when their breach becomes your incident\n"
                    "  - Offboard: keys, apps, groups, SSO, shared mailboxes"
                ),
                worked=(
                    "Pilot leftovers are third-party lifecycle failures. Revoke, then review how "
                    "they stayed for a year."
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
    17,
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
                    "an audit last year does not mean open RDP is fine today. Retention rules "
                    "often help investigations and audits together."
                ),
                formal="compliance requirements as drivers, not substitutes, for security controls",
                beats=(
                    "Compliance beats:\n"
                    "  1. Know applicable obligations at a high level\n"
                    "  2. Map controls to requirements with owners\n"
                    "  3. Evidence continuously, not only at audit week\n"
                    "  4. Fix say/do gaps"
                ),
                tech=(
                    "  - Map each requirement to a control owner and evidence location\n"
                    "  - Logging/retention may be compliance-driven and investigation-helpful\n"
                    "  - Privacy rules shape how investigation packs are shared\n"
                    "  - Contractual customer requirements can bind Boundry client work\n"
                    "  - Encrypted backups may satisfy a letter and still fail ransomware if online-only"
                ),
                worked=(
                    "Passing last year's audit does not bless this week's open RDP. "
                    "Meet the letter and the risk: encrypt backups and keep an offline/immutable copy. "
                    "Evidence habit: export MFA/CA configs monthly so audit week is not a scramble."
                ),
                how=(
                    "  1. Separate 'required by rule' from 'enough to be safe.'\n"
                    "  2. Prefer continuous evidence.\n"
                    "  3. Fix real exposure even if last audit passed."
                ),
                trap=(
                    "checkbox compliance while crown-jewel paths stay open. Near-miss: evidence "
                    "that exists only in one person's head."
                ),
                remember="Compliance is necessary. It is not automatic security.",
            ),
        ),
        (
            "Evidence habit",
            body(
                work="audit asks for MFA proof; you scramble screenshots from one laptop.",
                formal="continuous control evidence",
                beats=(
                    "Evidence habit: export configs, ticket trails, access reviews, training "
                    "completion on a cadence."
                ),
                tech=(
                    "  - SIEM/ticket history helps prove detective/response controls\n"
                    "  - Change tickets prove governance of exceptions\n"
                    "  - Store evidence where the next admin can find it"
                ),
                worked=(
                    "Teams that evidence monthly do not panic yearly. Scramble culture is a finding."
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
    17,
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
                    "identity controls. Findings get owners, due dates, fix evidence, and retest. "
                    "Vendor SOC reports inform diligence; they do not replace your access reviews."
                ),
                formal="audits vs assessments and finding remediation",
                beats=(
                    "Map:\n"
                    "  Internal audit → independence inside org varies by design\n"
                    "  External audit/assessment → outside party\n"
                    "  Finding → gap vs criteria\n"
                    "  Remediation → fix + evidence + retest / owner sign-off"
                ),
                tech=(
                    "  - Finding closure needs fix + evidence + owner sign-off, not a promise\n"
                    "  - Check scope exclusions that hide crown jewels\n"
                    "  - Self-assessment helps; independent audit claims need real independence\n"
                    "  - Vendor SOC reports inform diligence; they do not replace access reviews\n"
                    "  - Penetration tests and vuln scans are assessment types (next lesson contrast)"
                ),
                worked=(
                    "Finding: legacy auth enabled against policy. "
                    "Remediation: disable + evidence SigninLogs/CA export + owner sign-off. "
                    "If DC RDP was scoped out every year, the clean report is marketing."
                ),
                how=(
                    "  1. Identify audit vs assessment intent.\n"
                    "  2. Prefer owned remediation.\n"
                    "  3. Ask for evidence of closure."
                ),
                trap=(
                    "shelving findings until the next audit cycle without risk treatment. Near-miss: "
                    "trusting a clean report with suspicious scope exclusions."
                ),
                remember="Findings need owners and due dates, not binders.",
            ),
        ),
        (
            "Independence and scope",
            body(
                work="the team that built the firewall also 'audits' itself with no outside review.",
                formal="independence and scope clarity",
                beats=(
                    "Good practice: clear scope, criteria, independence appropriate to the claim."
                ),
                tech=(
                    "  - Self-assessment is useful but not the same as independent audit\n"
                    "  - Scope games hide crown jewels\n"
                    "  - Ask what was out of scope before celebrating a clean report"
                ),
                worked=(
                    "If DC RDP was scoped out every year, the clean report is marketing. "
                    "Widen scope or treat the exclusion as residual risk with an owner."
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
