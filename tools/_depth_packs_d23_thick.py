"""Option 1 deepen: overwrite thin D2/D3 DEPTH packs to the D1 word bar.

Executed by tools/_apply_option1_depth.py after base D2 packs and
_depth_packs_d345.py (body/put/DEPTH in globals).
Adds denser Technical specifics, worked examples, and tech near-miss traps.
Keeps work-facing picture + In Security+ terms bridge. No fluffy metaphors.
"""

# ---------------------------------------------------------------------------
# DOMAIN 2 (6 thin)
# ---------------------------------------------------------------------------
put(
    "sp_d2_05_vulns_human",
    17,
    [
        (
            "Humans are in the outline for a reason",
            body(
                orient=(
                    "Human and process gaps are real vulnerability classes on Security+. "
                    "A vulnerability is a weakness an attacker can use. Here the weakness "
                    "is people, process, or missing ownership, not only a CVE string."
                ),
                work=(
                    "finance pays from a single email without a callback. HR keeps clicking "
                    "macro invoices. A vendor VPN account has no review date. Awareness was "
                    "last updated fourteen months ago."
                ),
                formal="social engineering exposure, shadow IT, and process gaps as vulnerabilities",
                beats=(
                    "Human / process map:\n"
                    "  1. Social engineering success paths (phishing, BEC pressure)\n"
                    "  2. Password hygiene failures (reused Summer2026!)\n"
                    "  3. Missing travel / verification process\n"
                    "  4. Shadow IT and unsanctioned remote access\n"
                    "  5. No owner / no review date on exceptions"
                ),
                tech=(
                    "  - Process gap creates alert debt (travel login without HR note).\n"
                    "  - Callback on payment-change emails reduces BEC payoff.\n"
                    "  - Tech still required: ASR, MFA, disable legacy auth, DLP forwards.\n"
                    "  - Shadow IT smell: personal Gmail forward, rogue VPN, unsanctioned SaaS "
                    "with company data and no owner.\n"
                    "  - Exception without expiry is a standing vulnerability, same class as "
                    "an open management port with no ticket.\n"
                    "  - Reused seasonal passwords across many users turn spray into a "
                    "predictable hit rate."
                ),
                worked=(
                    "CEO travel login without HR note = process gap that forces extra "
                    "validation, not automatic ransomware.\n"
                    "Repeat Invoice.xlsm clicks = human vulnerability plus missing technical "
                    "macro controls (ASR / mail gateway).\n"
                    "Vendor VPN with no review date = process / governance gap. Prefer: owner "
                    "+ expiry + access review. Near-miss: ignore because 'the firewall exists.'"
                ),
                how=(
                    "  1. Name the human or process weakness.\n"
                    "  2. Pair coaching with a technical guardrail.\n"
                    "  3. Reject shame-only answers.\n"
                    "  4. Ask who owns the exception and when it expires."
                ),
                trap=(
                    "public shaming as the 'control,' or ignoring process gaps because a "
                    "firewall exists. Another near-miss: treating missing travel notes as "
                    "automatic ransomware true-positives with no other evidence."
                ),
                remember="Do not shame. Contain, coach, and redesign the path.",
            ),
        ),
        (
            "Contain and redesign",
            body(
                work=(
                    "after an unintentional click you isolate the host, reset the user, add "
                    "ASR, and schedule role-based awareness for finance. You do not dunk on "
                    "them in all-hands."
                ),
                formal="treating unintentional insider risk as a control failure, not a character failure",
                beats=(
                    "Good response framing:\n"
                    "  1. Contain impact\n"
                    "  2. Coach the person\n"
                    "  3. Add technical guardrails\n"
                    "  4. Fix ownership on the exception that allowed the path"
                ),
                tech=(
                    "  - Near-miss answer on the exam: only mock the clicker.\n"
                    "  - Strong answers: ASR + role training + MFA/legacy fixes.\n"
                    "  - Role-based awareness for finance beats org-wide poster-only.\n"
                    "  - After contain: open a ticket that names the process owner and the "
                    "technical control that should have blocked the path."
                ),
                worked=(
                    "Best response for unintentional insider: contain impact, coach, add "
                    "technical guardrails. Disable-all-accounts-forever is overkill theater. "
                    "Poster-only while Office can still launch powershell.exe is incomplete."
                ),
                how=(
                    "  1. Remove shame-only choices.\n"
                    "  2. Prefer dual-layer fixes (people + tech).\n"
                    "  3. Tie process gaps to owners and review dates."
                ),
                trap="'only fire the analyst' or 'only mock the clicker' when the path is still open.",
                remember="The control failed, including the people process. Fix both layers.",
            ),
        ),
    ],
)

put(
    "sp_d2_07_ioc_bec",
    18,
    [
        (
            "BEC indicator pack",
            body(
                orient=(
                    "BEC means business email compromise: abusing mail and identity to collect "
                    "information or redirect money. An indicator of compromise (IOC) is evidence "
                    "that abuse may be happening or already happened."
                ),
                work=(
                    "cfo@ gets a new inbox rule forwarding everything to personal Gmail. Client "
                    "used legacy auth. MFA was not prompted. Finance has a vendor payment-change "
                    "draft waiting."
                ),
                formal="mailbox collection / BEC indicators and identity-first containment",
                beats=(
                    "BEC IOC pack:\n"
                    "  1. New inbox rule or external forward-all\n"
                    "  2. Strange mail client / legacy auth / MFA skipped\n"
                    "  3. Finance-themed lure or payment-change language\n"
                    "  4. Unusual sign-in location or impossible travel without process"
                ),
                tech=(
                    "  - Contain: revoke sessions, remove rule, reset credentials, escalate\n"
                    "  - Eradicate contributors: disable legacy auth, alert/block external forwards\n"
                    "  - CIA lead impact: confidentiality / collection (mail still 'works')\n"
                    "  - MITRE-ish family: email/mailbox collection\n"
                    "  - Mailbox audit / unified audit: New-InboxRule, Set-Mailbox forwarding, "
                    "odd client apps\n"
                    "  - SigninLogs: legacy vs modern, MFA detail, location, impossible travel "
                    "context\n"
                    "  - Payment-change draft after rule creation = fraud staging, not 'busy CFO'"
                ),
                worked=(
                    "First fit mitigation: revoke sessions, remove rule, reset, escalate BEC.\n"
                    "Poster-only is incomplete. Closing as travel FP is how wire fraud happens.\n"
                    "Contrast: travel login + MFA + HR conference note with no rule and no "
                    "payment language = validate and document FP, not blind trust forever."
                ),
                how=(
                    "  1. Recognize the pack.\n"
                    "  2. Contain identity and mailbox persistence first.\n"
                    "  3. Warn finance / use callback process.\n"
                    "  4. Fix protocol debt after the firefight."
                ),
                trap=(
                    "'email is normal business, close FP' while an external forward-all rule "
                    "is live. Near-miss: awareness poster as the primary response while the "
                    "rule still forwards."
                ),
                remember="Rule + legacy auth + money language = contain now.",
            ),
        ),
        (
            "Near-miss responses",
            body(
                work="leadership wants only a company-wide poster after confirmed BEC.",
                formal="why awareness alone is incomplete after mailbox persistence",
                beats=(
                    "After containment:\n"
                    "  1. Finance callback on payment changes\n"
                    "  2. Disable legacy auth\n"
                    "  3. DLP / external forward controls\n"
                    "  4. Role-based awareness for finance"
                ),
                tech=(
                    "  - Payment-change draft after inbox rule = fraud staging\n"
                    "  - External forward-all = confidentiality / collection indicator\n"
                    "  - Eradication backlog: CA for risky sign-ins, forward controls, "
                    "disable legacy protocols that skip MFA"
                ),
                worked=(
                    "Awareness-only response to confirmed BEC is incomplete. Needs technical "
                    "identity/mail fixes. Opening inbound RDP 'so finance can check the "
                    "server' during BEC makes the blast radius worse."
                ),
                how=(
                    "  1. Reject poster-only primary answers.\n"
                    "  2. Prefer revoke/remove/reset.\n"
                    "  3. Add process for finance."
                ),
                trap="opening inbound RDP 'so finance can check the server' during BEC.",
                remember="Contain mailbox persistence first. Awareness comes after, not instead.",
            ),
        ),
    ],
)

put(
    "sp_d2_08_ioc_endpoint",
    18,
    [
        (
            "Encoded PowerShell tell",
            body(
                orient=(
                    "Endpoint indicators show what ran on a host. Parent/child process means "
                    "which program launched which child. Living-off-the-land means using "
                    "trusted built-in tools for hostile work."
                ),
                work=(
                    "WS-HR-03: excel.exe launches powershell.exe -enc from Invoice.xlsm in email. "
                    "No change ticket. Host still on the LAN."
                ),
                formal="malware execution / living-off-the-land indicators and host isolation",
                beats=(
                    "Endpoint IOC pack:\n"
                    "  1. Suspicious parent/child (Office → script host)\n"
                    "  2. -enc / encoded command (obfuscation, not encryption)\n"
                    "  3. Unsigned script, odd path, egress after launch\n"
                    "  4. No CHG explaining admin scripting"
                ),
                tech=(
                    "  - EDR tree into the ticket. Preserve evidence.\n"
                    "  - Do not decode malware on your hotspot admin laptop.\n"
                    "  - First containment: isolate host / network contain.\n"
                    "  - Hunt hash across mail gateway and other endpoints.\n"
                    "  - Capture pack: process tree, command line, hash, user, path, "
                    "network connects.\n"
                    "  - Living-off-the-land children: powershell, wscript, mshta, rundll32 "
                    "under Office parents.\n"
                    "  - Encoding (-enc / Base64) is obfuscation. Say it. Do not call it "
                    "encryption or AES confidentiality."
                ),
                worked=(
                    "excel → powershell -enc from Invoice.xlsm = suspicious execution: isolate.\n"
                    "'Excel is approved business software' is the classic near-miss close reason.\n"
                    "Wrong first IR move: leave on LAN overnight to see if files encrypt. "
                    "Watching ransomware finish is not analysis."
                ),
                how=(
                    "  1. Read parent/child, not only the child name.\n"
                    "  2. Treat -enc as obfuscation/tradecraft.\n"
                    "  3. Isolate before overnight 'curiosity.'\n"
                    "  4. Preserve EDR export before casual reimage when analysis still matters."
                ),
                trap=(
                    "leaving the host online to see if files encrypt by morning, or closing FP "
                    "because Office is approved. Near-miss: calling Base64 -enc 'encryption.'"
                ),
                remember="Approved app ≠ approved child behavior. Isolate first.",
            ),
        ),
        (
            "Approved app near-miss",
            body(
                work="someone argues Excel is on the allow list, so the alert must be wrong.",
                formal="living-off-the-land: trusted binaries used for hostile children",
                beats=(
                    "Remember:\n"
                    "  - Approved parents can launch malicious children\n"
                    "  - Base64 -enc is not AES confidentiality\n"
                    "  - Containment beats curiosity"
                ),
                tech=(
                    "  - Wrong first move: leave on LAN overnight\n"
                    "  - Right pack: isolate, preserve EDR, escalate, hunt campaign/hash\n"
                    "  - After isolate: check mail gateway for the same attachment hash "
                    "and other recipients"
                ),
                worked=(
                    "Wrong first IR move after confirmed -enc chain: leave on LAN to watch "
                    "encryption. Watching ransomware finish is not analysis. Correct: isolate, "
                    "preserve tree, hunt the campaign."
                ),
                how=(
                    "  1. Reject 'approved app' as sole close reason.\n"
                    "  2. Prefer isolate + hunt.\n"
                    "  3. Keep encoding vs encryption straight."
                ),
                trap="decoding unknown -enc blobs on a production admin workstation.",
                remember="Parent/child + encoded command + email lure = execution chain.",
            ),
        ),
    ],
)

put(
    "sp_d2_09_ioc_network",
    18,
    [
        (
            "Exposure vs probe",
            body(
                orient=(
                    "Network indicators tell you whether a path was open, used, or blocked. "
                    "ALLOW means the firewall permitted the flow. DROP or DENY means it blocked "
                    "that try."
                ),
                work=(
                    "one firewall story is DROP bursts on TCP 445 with no internal follow-on. "
                    "Another is ALLOW tcp/3389 from the internet to PROD-DC01."
                ),
                formal="ALLOW versus DROP as different incident classes, plus lateral movement and C2 smells",
                beats=(
                    "Network IOC map:\n"
                    "  1. Exposure: ALLOW on management ports to crown jewels\n"
                    "  2. Probe: DROP/deny bursts that never get through\n"
                    "  3. Lateral movement: odd admin shares / remote services after phishing\n"
                    "  4. C2 / beaconing: steady odd egress, rare ports, staged binaries calling out"
                ),
                tech=(
                    "  - Pair firewall with EDR and identity. Firewall alone is incomplete.\n"
                    "  - ALLOW means path open or used. DROP means perimeter held for that try.\n"
                    "  - Internet RDP to a DC is critical exposure even with no CVE string.\n"
                    "  - Ports to know: 3389 RDP, 22 SSH, 445 SMB, 53 DNS, 443 HTTPS, "
                    "VPN often UDP 500/4500 or TLS VPN.\n"
                    "  - Beaconing: regular callback rhythm to a rare destination/port after "
                    "a phishing or macro event.\n"
                    "  - Do not open more inbound management ports to 'investigate live.'"
                ),
                worked=(
                    "Internet SMB 445 DROP, no lateral = commodity probe; note IOC.\n"
                    "ALLOW 3389 to PROD-DC01 = critical exposure / investigate and remove.\n"
                    "Auth from HR PC to DC admin shares after phishing = possible lateral "
                    "movement. Corroborate with EDR and identity before closing as noise."
                ),
                how=(
                    "  1. Read ALLOW vs DROP first.\n"
                    "  2. Check asset tier.\n"
                    "  3. Corroborate with host/identity.\n"
                    "  4. Match urgency to path, not to row count."
                ),
                trap=(
                    "paging DROP noise like domain compromise, or treating ALLOW 3389 as INFO "
                    "because volume is low. Near-miss: firewall-only forever with no host "
                    "context on a lateral-looking path."
                ),
                remember="ALLOW means path open or used; DROP means perimeter held.",
            ),
        ),
        (
            "Lateral and C2 smells",
            body(
                work=(
                    "after a phishing click, WS-HR-03 suddenly authenticates to PROD-DC01 admin "
                    "shares, or a new binary beacons every five minutes to a rare port."
                ),
                formal="lateral movement and command-and-control (C2) network indicators",
                beats=(
                    "Hunt beats:\n"
                    "  1. New east-west admin traffic after phishing\n"
                    "  2. Steady callback rhythm (beaconing)\n"
                    "  3. Escalate and contain the host path"
                ),
                tech=(
                    "  - Best pairing: firewall + EDR/identity context\n"
                    "  - Do not open more ports to 'investigate live'\n"
                    "  - VPN user mapping helps tie remote ALLOW rows to a person\n"
                    "  - DNS query names beside rare egress often explain the C2 smell"
                ),
                worked=(
                    "Beaconing ≈ steady suspicious egress / callback pattern.\n"
                    "Internet RDP to DC with no VPN = critical network exposure indicator.\n"
                    "One successful path to a crown jewel beats a thousand DROPs on noise."
                ),
                how=(
                    "  1. Name exposure vs probe vs lateral vs C2.\n"
                    "  2. Pick containment that matches.\n"
                    "  3. Corroborate sources."
                ),
                trap="firewall-only forever with no host context on a lateral-looking path.",
                remember="Even one successful path to a crown jewel beats a thousand DROPs.",
            ),
        ),
    ],
)

put(
    "sp_d2_10_mitigate_identity",
    18,
    [
        (
            "Match mitigation to pattern",
            body(
                orient=(
                    "Mitigation means the control that interrupts the attack path you named. "
                    "For identity and email, match the control to spray, brute force, or BEC."
                ),
                work=(
                    "after spray you want MFA and smart lockout. After BEC you revoke sessions "
                    "and disable legacy auth. You do not answer 'more dashboards' while the path "
                    "stays open."
                ),
                formal="identity and email mitigations matched to spray, brute, and BEC patterns",
                beats=(
                    "Mitigation map:\n"
                    "  Spray → MFA, smart lockout, block bad IPs, hunt successes, password hygiene\n"
                    "  BEC → revoke sessions, remove rules, disable legacy auth, DLP/external\n"
                    "         forward controls, CA for risky sign-ins, finance callback\n"
                    "  Malware execution → isolate host (not identity-poster theater)"
                ),
                tech=(
                    "  - Purpose of MFA: stolen/guessed passwords become insufficient alone\n"
                    "  - Purpose of disabling legacy auth: force modern auth that can demand MFA/CA\n"
                    "  - External forward block = confidentiality / exfil mitigation\n"
                    "  - Smart lockout: slow attacks while limiting collateral lockouts\n"
                    "  - Conditional Access (CA): policy around identity, device, location, risk\n"
                    "  - After spray: hunt successful 4624 / SigninLogs success from attacking IP\n"
                    "  - Detect-only (more SIEM panels) is incomplete while legacy auth still works"
                ),
                worked=(
                    "Primary MFA purpose against spray: make password-only attacks fail more.\n"
                    "Best BEC technical pair: disable legacy auth + block/alert external forwards.\n"
                    "Leaving a malware host up to observe encryption is the wrong mitigation "
                    "class (that needs isolate, not an identity poster)."
                ),
                how=(
                    "  1. Name the pattern.\n"
                    "  2. Pick the mitigation that closes that path.\n"
                    "  3. Prefer purpose language over brand names.\n"
                    "  4. Prefer prevent/correct before detect-only when the path is open."
                ),
                trap=(
                    "awareness poster only for open RDP, or detect-only answers when the "
                    "question asks to mitigate. Near-miss: picking MFA branding without "
                    "saying what it stops."
                ),
                remember="Purpose first, brand name second. Close the path.",
            ),
        ),
        (
            "Purpose of the technique",
            body(
                work="exam wording says 'what is the purpose of disabling legacy authentication?'",
                formal="explaining why a mitigation exists, in ops language",
                beats=(
                    "Purpose lines to memorize:\n"
                    "  - MFA raises authentication strength\n"
                    "  - Disabling legacy auth forces modern paths that support MFA/CA\n"
                    "  - Forward controls stop mail leaving\n"
                    "  - Smart lockout slows spray/brute without DOSing the company"
                ),
                tech=(
                    "  - If path is still open, detective-only is incomplete\n"
                    "  - Match control to vector every time\n"
                    "  - Legacy protocols often skip MFA prompts. That is why they matter "
                    "in BEC stories."
                ),
                worked=(
                    "Picking 'awareness poster only' for open RDP is wrong: remove the exposure.\n"
                    "Purpose of disable legacy auth: force modern auth that can demand MFA/CA, "
                    "not 'make Outlook prettier.'"
                ),
                how=(
                    "  1. Translate purpose → what it stops.\n"
                    "  2. Eliminate answers that ignore the open path.\n"
                    "  3. Keep containment timing straight."
                ),
                trap="choosing a tool that does not interrupt the kill chain in the question.",
                remember="Pick the mitigation that interrupts the kill chain you named.",
            ),
        ),
    ],
)

put(
    "sp_d2_11_mitigate_segment",
    18,
    [
        (
            "Enterprise mitigations that show up in Boundry",
            body(
                orient=(
                    "Beyond identity, you mitigate with segmentation, hardening, patching, "
                    "isolation, and monitoring. Segmentation separates trust tiers so one "
                    "breach does not freely reach everything."
                ),
                work=(
                    "you remove internet RDP, put admins on a jump host, turn on ASR so Office "
                    "cannot launch script hosts, patch the VPN client, and isolate a host that "
                    "already ran malware. SIEM still watches, but watching alone is not enough."
                ),
                formal="segmentation, hardening, patching, isolation, and monitoring as mitigation classes",
                beats=(
                    "Purpose map:\n"
                    "  Segmentation / deny 3389: shrink blast radius, remove exposure\n"
                    "  Hardening / ASR: stop Office → script hosts\n"
                    "  Patching: reduce exploitability of known vulns\n"
                    "  Isolation: corrective containment after execution\n"
                    "  Monitoring (SIEM/EDR): detective layer; necessary, not sufficient alone"
                ),
                tech=(
                    "  - Exposed RDP → remove path / VPN+PAM (not another dashboard)\n"
                    "  - Macro malware → ASR + mail controls + isolate if already running\n"
                    "  - Unpatched VPN → patch/replace, then monitor\n"
                    "  - Monitoring without removing open 3389 = detective coverage on an\n"
                    "    unfixed preventive failure\n"
                    "  - Jump / PAM: broker admin access; deny user VLANs to DC admin ports "
                    "by default\n"
                    "  - Isolation timing: after suspected/confirmed execution, not instead "
                    "of never writing tickets"
                ),
                worked=(
                    "Best mitigation for internet RDP to DC: remove internet RDP; VPN+MFA+jump/PAM; "
                    "segment.\n"
                    "Purpose of isolation after malware: corrective stop-spread.\n"
                    "ASR blocking Office→child script = hardening / preventive endpoint mitigation.\n"
                    "Near-miss: more SIEM panels as the primary fix for internet RDP to a DC."
                ),
                how=(
                    "  1. Identify the open path or failed host.\n"
                    "  2. Prefer cheapest reliable interrupt, preferably before execution.\n"
                    "  3. Do not confuse detect with prevent."
                ),
                trap="more SIEM panels as the primary fix for internet RDP to a DC.",
                remember="Interrupt the kill chain at the cheapest reliable step.",
            ),
        ),
        (
            "Pick the fit",
            body(
                work="question offers four mitigations; only one matches the failure class.",
                formal="matching mitigation class to failure class under time pressure",
                beats=(
                    "Quick fit:\n"
                    "  Path open → remove / segment\n"
                    "  Code ran → isolate\n"
                    "  Known vuln → patch\n"
                    "  Need visibility → monitor (plus a preventive fix if path is open)"
                ),
                tech=(
                    "  - Isolation timing: after suspected/confirmed execution\n"
                    "  - Segmentation purpose: limit blast radius / separate trust tiers\n"
                    "  - Patching purpose: remove known exploitable weakness after discover\n"
                    "  - Hardening purpose: shrink attack surface before the alert fires"
                ),
                worked=(
                    "When is isolation the right mitigation? After suspected/confirmed execution "
                    "on a host, not instead of tickets forever.\n"
                    "When is segmentation right? When the question shows free east-west or "
                    "internet management paths to crown jewels."
                ),
                how=(
                    "  1. Name failure class.\n"
                    "  2. Eliminate wrong-timing answers.\n"
                    "  3. Choose path-closing control when asked to mitigate exposure."
                ),
                trap="using isolation as a substitute for never writing tickets or never patching.",
                remember="Detect ≠ prevent. Architecture fixes beat detective-only.",
            ),
        ),
    ],
)

# ---------------------------------------------------------------------------
# DOMAIN 3 (6 thin)
# ---------------------------------------------------------------------------
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
                    "privilege, and validate continuously. Microsegmentation means splitting "
                    "networks into small trust zones so malware cannot freely roam."
                ),
                work=(
                    "CEO travel login is allowed because MFA passed and HR confirmed travel, "
                    "not because 'they are on VPN.' HR PCs should not talk to DC admin ports "
                    "by default."
                ),
                formal="Zero Trust and microsegmentation as architecture, not a product sticker",
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
                    "  - Travel + MFA + process is ZT-aligned ops\n"
                    "  - Conditional Access examples: require MFA for admins, block legacy "
                    "auth, require compliant device for sensitive apps\n"
                    "  - Flat network after phishing = lateral movement becomes trivial"
                ),
                worked=(
                    "Trusting 'inside VPN' with no MFA is not Zero Trust.\n"
                    "Microsegmentation stops HR malware from freely hitting DC admin ports.\n"
                    "Disabling MFA for executives 'for convenience' breaks ZT / strong AuthN "
                    "assumptions. Prefer: MFA + travel process + least privilege."
                ),
                how=(
                    "  1. Reject location-alone trust answers.\n"
                    "  2. Prefer per-session verify + least privilege.\n"
                    "  3. Match architecture control to failure class (see PBQ)."
                ),
                trap=(
                    "'VPN equals trusted' or disabling MFA for executives for convenience. "
                    "Near-miss: buying a Zero Trust sticker while 3389 still faces the internet."
                ),
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
                formal="choosing architecture controls by failure class",
                beats=(
                    "Fit map:\n"
                    "  Open 3389 → remove exposure / VPN + PAM jump\n"
                    "  Travel inconsistency → ZT / Conditional Access + travel process\n"
                    "  Legacy-auth inbox rule → disable legacy auth + session/inbox policy\n"
                    "  Macro→PS → mail gateway + EDR ASR"
                ),
                tech=(
                    "  - Architecture answers remove paths; dashboards alone do not\n"
                    "  - Least privilege shrinks what a stolen session can do\n"
                    "  - svc accounts: no interactive login, no Domain Admin for backup jobs "
                    "that only need backup rights"
                ),
                worked=(
                    "ALLOW 3389 from internet → remote exposure fix.\n"
                    "Inbox rule without MFA because legacy auth → identity architecture fix.\n"
                    "Macro→PS on HR PC → endpoint/mail architecture (ASR), not 'trust the VLAN.'"
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
    18,
    [
        (
            "Secure the network path",
            body(
                orient=(
                    "Infrastructure security for networks means placing controls where traffic "
                    "flows. A secure baseline starts with deny-by-default on management planes "
                    "and brokered admin access."
                ),
                work=(
                    "prod DC management should not be reachable from the open internet. Admin "
                    "work happens through VPN + jump/PAM. East-west traffic from HR to DC admin "
                    "ports is denied by default."
                ),
                formal="secure network infrastructure: firewall placement, segmentation, secure remote access",
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
                    "    closing internet RDP to a DC\n"
                    "  - Prefer explicit source/destination/port on crown-jewel ALLOWs. "
                    "ANY/ANY is a finding.\n"
                    "  - Admin paths: VPN (UDP 500/4500 or TLS VPN) + jump/PAM beats inbound "
                    "TCP 3389.\n"
                    "  - WAF helps HTTP(S) app classes. It does not close non-HTTP management ports."
                ),
                worked=(
                    "Best first fix for internet RDP to a DC: remove exposure; VPN/PAM/MFA jump.\n"
                    "More dashboards only is the near-miss.\n"
                    "Encrypted VPN without MFA is a honeymoon, not complete remote architecture. "
                    "Add MFA / CA and brokered admin."
                ),
                how=(
                    "  1. Find the open management path.\n"
                    "  2. Prefer remove/segment over detect-only.\n"
                    "  3. Keep admin paths brokered."
                ),
                trap=(
                    "leaving 3389 open 'temporarily' without owner, expiry, or compensating "
                    "broker. Near-miss: equating 'firewall exists' with 'path is closed.'"
                ),
                remember="Close management paths. Segment trust tiers.",
            ),
        ),
        (
            "Devices and rules that matter",
            body(
                work="a change opens a wide ANY/ANY rule 'to troubleshoot' and never closes it.",
                formal="firewall rule hygiene as infrastructure security",
                beats=(
                    "Rule hygiene:\n"
                    "  1. Least privilege ports/sources\n"
                    "  2. Change ticket + expiry on exceptions\n"
                    "  3. Log and review high-risk ALLOWs"
                ),
                tech=(
                    "  - ANY/ANY is an architecture failure waiting for an IOC\n"
                    "  - Pair rule reviews with asset inventory\n"
                    "  - Allow-list JUMP-01 / scanners with CHG + firewall/IDS tuning together\n"
                    "  - When SIEM shows scanner noise, still confirm no unexpected ALLOW "
                    "appeared beside it"
                ),
                worked=(
                    "Wide troubleshooting ALLOW without expiry becomes permanent exposure. "
                    "Treat it like a gap. Default-deny with explicit crown-jewel rules is the "
                    "strong baseline."
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
    18,
    [
        (
            "Endpoints and cloud control planes",
            body(
                orient=(
                    "Endpoints and cloud consoles are infrastructure too. Hardening them closes "
                    "common Domain 2 paths. The control plane is where admins change identity, "
                    "network, and storage settings."
                ),
                work=(
                    "HR PCs get EDR + ASR. Cloud admin portals require MFA and Conditional "
                    "Access. Storage accounts are not public 'for convenience.'"
                ),
                formal="endpoint hardening and cloud security posture as infrastructure controls",
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
                    "  - Admin consoles are crown jewels equal to DCs\n"
                    "  - Endpoint desk clues: EDR health, ASR rules, local admin count, "
                    "BitLocker status, patch age\n"
                    "  - Cloud desk clues: MFA on Global Admin / Owner roles, PIM/JIT if "
                    "available, no public storage with sensitive exports\n"
                    "  - Secrets in repos and chat are infrastructure findings, not style notes"
                ),
                worked=(
                    "Macro path needs endpoint architecture (ASR) plus mail controls.\n"
                    "Public cloud storage with sensitive exports is an infra misconfig, not "
                    "'SaaS magic.'\n"
                    "Local admin on every HR PC breaks least privilege and turns every phishing "
                    "click into an easier install path."
                ),
                how=(
                    "  1. Ask which plane failed: device or cloud control plane.\n"
                    "  2. Pick hardening that removes that path.\n"
                    "  3. Keep shared responsibility in mind."
                ),
                trap=(
                    "hardening laptops while leaving cloud root keys in a shared chat. "
                    "Near-miss: BitLocker as the answer when the story is Office→script on "
                    "an unlocked session."
                ),
                remember="Endpoint and cloud consoles are infrastructure attack surfaces.",
            ),
        ),
        (
            "Baseline and drift",
            body(
                work="a golden image had ASR on, but a department image quietly turned it off.",
                formal="configuration baselines and drift as architecture/ops overlap",
                beats=(
                    "Baseline beats:\n"
                    "  1. Define required controls\n"
                    "  2. Deploy consistently\n"
                    "  3. Detect drift\n"
                    "  4. Fix with change process"
                ),
                tech=(
                    "  - Drift check: compare baseline GPO/Intune/ASR to what HR images "
                    "actually run\n"
                    "  - Private endpoints / private links keep services off the public "
                    "internet when the design allows\n"
                    "  - NSG 0.0.0.0/0:3389 to a domain-joined VM is the same failure class "
                    "as on-prem internet RDP"
                ),
                worked=(
                    "Golden image Monday, HR laptop Friday with local admin and ASR off = "
                    "hardening failed. Reopen the baseline ticket. Do not mark done."
                ),
                how=(
                    "  1. Ask if the baseline still holds.\n"
                    "  2. Prefer verify-after-deploy answers.\n"
                    "  3. Treat cloud NSG exposure like on-prem firewall exposure."
                ),
                trap="assuming the golden image equals every live laptop forever.",
                remember="Baselines fail when drift is invisible. Measure and fix.",
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
                    "and in use (being processed). Controls differ by state. Classification "
                    "is the label that says how sensitive the data is."
                ),
                work=(
                    "TLS protects the Boundry dashboard in transit. BitLocker protects a stolen "
                    "laptop at rest. A screen privacy filter and least privilege help data in use "
                    "on a shared desk."
                ),
                formal="protecting data by state with the matching control type",
                beats=(
                    "State map:\n"
                    "  In transit → TLS/VPN/SSH\n"
                    "  At rest → BitLocker, encrypted backups, encrypted cloud storage\n"
                    "  In use → access control, DLP endpoints, clean desk / privacy, rights management"
                ),
                tech=(
                    "  - Hashing is not encryption for confidentiality of contents\n"
                    "  - Classification labels drive which control is required\n"
                    "  - BEC forward attacks confidentiality of mail contents (often stored/"
                    "in-use mail, not a TLS failure)\n"
                    "  - In transit check: browser TLS, SMTP/TLS, VPN. Cleartext login pages "
                    "fail this state.\n"
                    "  - At rest check: BitLocker/FileVault, encrypted backups, encrypted "
                    "cloud objects.\n"
                    "  - In use check: who can open the file now (ACL/DLP/rights), not only "
                    "disk encryption.\n"
                    "  - Exam near-miss: answering BitLocker when the story is an HTTP "
                    "password form."
                ),
                worked=(
                    "Stolen unencrypted laptop = at-rest confidentiality failure.\n"
                    "HTTP login page = in-transit failure.\n"
                    "Correct control must match the state the question describes.\n"
                    "Near-miss: BitLocker for a cleartext web login, or TLS for a stolen "
                    "unencrypted disk with no network story."
                ),
                how=(
                    "  1. Name the data state.\n"
                    "  2. Pick the control for that state.\n"
                    "  3. Do not answer BitLocker for a TLS question or vice versa."
                ),
                trap=(
                    "picking disk encryption when the question is clearly about data in "
                    "transit. Another near-miss: calling a hash of a password 'encrypting "
                    "the file at rest.'"
                ),
                remember="Match the control to the data state in the question.",
            ),
        ),
        (
            "Classification drives control",
            body(
                work="payroll exports get a higher label than the public marketing PDF.",
                formal="data classification as the driver for encryption, DLP, and access rules",
                beats=(
                    "Classification beats:\n"
                    "  1. Label sensitivity\n"
                    "  2. Bind handling rules\n"
                    "  3. Enforce with technical controls where possible"
                ),
                tech=(
                    "  - Public vs internal vs confidential vs restricted\n"
                    "  - Mislabeling causes both overblocking and silent leakage\n"
                    "  - Confidential payroll CSV in a public share fails classification "
                    "and technical enforcement together"
                ),
                worked=(
                    "Confidential payroll CSV in a public share is a classification + control "
                    "failure. Fix the label and the share ACL/encryption, not only one."
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
                    "data leaving approved channels. Encryption hides contents with keys. "
                    "They answer different failure modes and often work together."
                ),
                work=(
                    "DLP alerts when payroll CSVs upload to personal cloud. Encryption protects "
                    "the laptop disk and the HTTPS session. An external mail forward rule is a "
                    "DLP/policy miss waiting to happen."
                ),
                formal="DLP and encryption as complementary data protections",
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
                    "  - BitLocker does not stop upload from an unlocked session\n"
                    "  - TLS does not stop a valid session from creating an external "
                    "forward rule.\n"
                    "  - DLP/forward controls and encryption answer different failure modes. "
                    "Often you need both.\n"
                    "  - Keys beside ciphertext (backup key on the same share) fail "
                    "'appropriate use.'"
                ),
                worked=(
                    "Confirmed BEC forward: revoke sessions + remove rule + DLP/forward policy. "
                    "TLS alone would not have stopped the forward.\n"
                    "Near-miss: answering BitLocker for a mailbox forward question, or DLP "
                    "for a stolen cleartext disk with no upload story."
                ),
                how=(
                    "  1. Ask if the problem is hiding bits or stopping an exfil path.\n"
                    "  2. Pick encryption vs DLP accordingly.\n"
                    "  3. Often you need both layers."
                ),
                trap=(
                    "answering BitLocker for a mailbox forward question, or DLP for a stolen "
                    "cleartext disk with no upload story."
                ),
                remember="Encryption hides. DLP polices where data may go.",
            ),
        ),
        (
            "Keys and appropriate use",
            body(
                work="backups are 'encrypted' but the key sits on the same share as the backup.",
                formal="appropriate cryptographic use includes key management",
                beats=(
                    "Key beats:\n"
                    "  1. Separate keys from ciphertext when possible\n"
                    "  2. Manage cert lifetimes\n"
                    "  3. Prefer platform-managed keys over chat-pasted secrets"
                ),
                tech=(
                    "  - Expired certs create trust/availability friction\n"
                    "  - Hard-coded API keys in repos are data/crypto failures\n"
                    "  - Base64 is encoding, not encryption. Do not call a Base64 blob "
                    "an encrypted backup."
                ),
                worked=(
                    "Encrypted backup with key beside it is weak appropriate-use. Fix key "
                    "custody. Calling any Base64 blob 'encrypted backups' is the classic "
                    "near-miss."
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
    17,
    [
        (
            "Stay up when parts fail",
            body(
                orient=(
                    "Resilience means the system keeps serving through failures. High availability "
                    "(HA) uses redundant components so one failure does not take everything down. "
                    "A single point of failure is one component whose loss takes down the service."
                ),
                work=(
                    "two DNS servers, clustered load balancers, and a secondary site for critical "
                    "apps. A single jump host with no spare is a resilience gap for admin access."
                ),
                formal="resilience and high availability architecture",
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
                    "  - VPN concentrator HA matters for remote work continuity\n"
                    "  - Name the SPOF: one VPN concentrator, one DNS, one MFA provider, "
                    "one jump host\n"
                    "  - HA pairs that share the same ransomware-accessible backup identity "
                    "still fail recovery\n"
                    "  - Hot / warm / cold sites trade cost vs how ready the alternate site is"
                ),
                worked=(
                    "Dual firewalls in HA help availability of the path. They do not replace "
                    "offline backups if both see the same ransomware-encrypted share logic.\n"
                    "Warm site: partial readiness between hot (live twin) and cold (empty-ish). "
                    "Pick site type to match RTO."
                ),
                how=(
                    "  1. Ask if the question wants uptime or recoverability.\n"
                    "  2. HA for uptime; backups/DR for restore.\n"
                    "  3. Look for single points of failure."
                ),
                trap=(
                    "calling HA a substitute for backups, or backups a substitute for removing "
                    "single points of failure. Near-miss: untested failover diagrams presented "
                    "as resilience."
                ),
                remember="HA keeps the lights on. Backups bring data back.",
            ),
        ),
        (
            "Design for failure",
            body(
                work="the only MFA/SMS provider dies and nobody can authenticate.",
                formal="avoiding brittle dependencies in resilience design",
                beats=(
                    "Brittleness checks:\n"
                    "  1. Auth path redundancy / break-glass\n"
                    "  2. Power / ISP diversity for critical sites\n"
                    "  3. Documented failover owners"
                ),
                tech=(
                    "  - Break-glass accounts with tight monitoring\n"
                    "  - Test failover on a schedule\n"
                    "  - Redundant ISP links mainly help availability of connectivity\n"
                    "  - Backup admin that is Domain Admin everywhere: compromise of the "
                    "backup plane kills resilience"
                ),
                worked=(
                    "Single SMS provider with no alternate auth factor is an availability risk "
                    "disguised as an MFA success story. Prefer alternate factors + monitored "
                    "break-glass."
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
    18,
    [
        (
            "RTO, RPO, and backups that work",
            body(
                orient=(
                    "RTO means recovery time objective: how quickly you must restore service. "
                    "RPO means recovery point objective: how much data loss (in time) you can "
                    "tolerate. Backups are how you often meet those numbers. Immutable means "
                    "the copy cannot be altered or deleted for a retention window."
                ),
                work=(
                    "finance says RTO 4 hours and RPO 15 minutes for the billing DB. That means "
                    "more than nightly backups. You also need offline/immutable copies so "
                    "ransomware cannot encrypt the only backup."
                ),
                formal="backup strategy tied to RTO/RPO, including ransomware-resistant copies",
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
                    "  - Hot/warm/cold sites trade cost vs RTO\n"
                    "  - Nightly backup alone fails a 15-minute RPO. You need frequent snapshots "
                    "or continuous replication that match the RPO number.\n"
                    "  - Online-only backups fail ransomware scenarios even if HA looks pretty.\n"
                    "  - Separate backup identity from Domain Admin. Monitor it.\n"
                    "  - Encrypt backups and keep keys off the same share as the ciphertext."
                ),
                worked=(
                    "Nightly backup alone fails a 15-minute RPO.\n"
                    "Online-only backups fail ransomware scenarios even if HA looks pretty.\n"
                    "Question: RPO 15 minutes, only nightly jobs. Answer: backup frequency does "
                    "not meet RPO. Near-miss: 'we have Veeam' without frequency or offline copy."
                ),
                how=(
                    "  1. Read RTO vs RPO carefully.\n"
                    "  2. Match backup design to both.\n"
                    "  3. Prefer answers that include test + offline copy for ransomware "
                    "questions."
                ),
                trap=(
                    "mixing RTO and RPO, or assuming HA clusters meet RPO without backup "
                    "frequency. Near-miss: green backup jobs without restore proof."
                ),
                remember="RPO = how much data loss. RTO = how fast back up. Test restores.",
            ),
        ),
        (
            "Restore is the control",
            body(
                work="backups succeed every night; nobody has restored billing in eighteen months.",
                formal="tested restore as part of resilience, not optional paperwork",
                beats=(
                    "Restore beats:\n"
                    "  1. Schedule restore tests\n"
                    "  2. Measure actual time vs RTO\n"
                    "  3. Document who runs the restore"
                ),
                tech=(
                    "  - A backup you cannot restore is not a control\n"
                    "  - Include identity/cloud SaaS export strategies where relevant\n"
                    "  - If restore test takes 18h and RTO is 4h, you failed RTO. Fix process, "
                    "parallelism, or site readiness.\n"
                    "  - Immutable / offline copy purpose: survive online encryption of primary "
                    "and connected backup planes"
                ),
                worked=(
                    "Untested backups are a resilience gap even when green checkmarks fill the "
                    "dashboard. 'We have Veeam' is not enough after ransomware if copies are "
                    "online-only and identity is shared with Domain Admin."
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
    17,
    [
        (
            "Continuity plans you actually rehearse",
            body(
                orient=(
                    "Business continuity keeps critical business functions running. Disaster "
                    "recovery brings IT services back after a major disruption. Both need testing. "
                    "A tabletop is a discussion exercise. A restore or failover test proves the "
                    "technical path."
                ),
                work=(
                    "tabletop for ransomware, technical failover test for the VPN pair, and a "
                    "phone tree that still has last year's on-call list."
                ),
                formal="BCP/DR testing and after-action improvement",
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
                    "  - Scope tests to critical processes first\n"
                    "  - Tabletop finds decision/people gaps. Technical failover finds "
                    "restore/path gaps. You need both over time.\n"
                    "  - Include critical vendors/MSPs when they sit on the restore or "
                    "comms path.\n"
                    "  - After-action items need owner + due date or the exercise was theater."
                ),
                worked=(
                    "A beautiful DR binder with no test in two years is weaker than a messy "
                    "plan that was tabletopped last quarter and patched.\n"
                    "Tabletop vs restore test: tabletop stresses decisions; restore test "
                    "stresses technical restore time vs RTO."
                ),
                how=(
                    "  1. Ask if the plan was tested.\n"
                    "  2. Prefer answers that include lessons learned + updates.\n"
                    "  3. Separate BCP (business) from DR (IT) when the question does."
                ),
                trap=(
                    "assuming documentation alone equals continuity. Near-miss: closing an "
                    "exercise with 'went fine' when payments approval failed."
                ),
                remember="Untested continuity plans fail on contact lists and restore steps first.",
            ),
        ),
        (
            "After-action loop",
            body(
                work=(
                    "failover worked, but finance could not approve emergency spend because the "
                    "approver was unreachable."
                ),
                formal="improving continuity from exercise findings",
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
                    "  - Keep break-glass and comms out-of-band options\n"
                    "  - Update contact trees after every exercise\n"
                    "  - After a real BEC, continuity docs should update with lessons and owners"
                ),
                worked=(
                    "Exercise finding without an owner is theater. Assign and due-date it.\n"
                    "Best evidence of DR readiness: measured restore/failover on a cadence, "
                    "not a binder never opened."
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
