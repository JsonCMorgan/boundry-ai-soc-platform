"""Legacy D2 specs (unused by build). Active Domain 2 source is gen_secplus_d2b.py.

build_secplus_phase1.py imports gen_secplus_d2b. Keep this file only as historical
reference, or delete later. Voice guide lives in tools/build_secplus_phase1.py.
"""
from __future__ import annotations

from gen_secplus_phase1 import _mc, _qz, _wrap  # type: ignore  # noqa: loaded via exec


def d2_specs(add):
    """Register Domain 2 micro-lessons (11) onto add()."""

    add(
        "sp_d2_01_threat_actors", "d2_threats", "2.1",
        "Threat actors and motivations", 10,
        ["Threat Actor", "Insider Threat", "Ransomware", "Hacktivist"],
        [
            ("Motivation drives urgency", """
                Hire-manager version — motivation drives containment urgency:

                  Nation-state — persistence, stealth, long dwell
                  Organized crime / ransomware — money; spray → valid creds → ransomware
                  Hacktivist — disruption / message
                  Insider (intentional) — new local admin with no ticket; data staging
                  Insider (unintentional) — CFO clicks Invoice.xlsm; CEO travel without a note
                  Shadow IT / weak admin — exposed RDP 'just for the vendor'
                  Script kiddie / commodity — internet SMB 445 probes your firewall DROPs

                Motivation is why you escalate DC RDP faster than a noisy 445 scan that never got through.
                """),
            ("Boundry talk-track", """
                You will rarely prove 'nation-state' on a 15-minute alert. You will say:
                'Motivation looks commodity/crime — identity and email are the paths —
                I am containing for ransomware stage-1, not writing an APT novel.'
                """),
        ],
        [
            _mc("Spray → valid creds → encrypt shares. Most likely actor motivation class?",
                ["Hacktivist protest only", "Organized crime / ransomware economics",
                 "Only physical thief", "Benign CHG-512"], 1,
                "Money path through identity.",
                "Crime crews monetize access. Treat spray as stage-0 of that path."),
            _mc("New local admin at 03:14, no ticket. Actor profile to keep on the table?",
                ["Only script kiddie 445 noise", "Insider or compromised admin identity",
                 "Only printer toner", "Authorized Nessus"], 1,
                "Privileged change without process.",
                "Intentional insider or stolen admin creds both fit until proven otherwise."),
            _mc("Internet SMB 445 DROP with no lateral movement. Best actor take?",
                ["Domain compromise tonight", "Commodity probe; perimeter held — note IOC",
                 "Identical to ALLOW 3389 on DC", "Proof of CFO BEC"], 1,
                "DROP ≠ breach.",
                "Failed inbound probe is not the same class as exposed RDP ALLOW."),
        ],
        [
            _qz("q_d2_01a", "Why escalate internet RDP to a DC faster than DROP 445 noise?",
                ["Fonts", "High-value path + likely crime/ransomware stage risk",
                 "445 is always worse", "RDP is always FP"], 1,
                "Asset tier + successful path matter."),
            _qz("q_d2_01b", "Unintentional insider example in Boundry stories:",
                ["Nation-state implant only", "CFO clicks Invoice.xlsm macro lure",
                 "Firewall DENY working", "Documented CHG scan"], 1,
                "Human vector, not malice."),
            _qz("q_d2_01c", "Shadow IT exposing RDP is closest to:",
                ["Strong Zero Trust", "Poorly skilled / unsanctioned admin risk",
                 "Perfect compensating control", "Hashing"], 1,
                "Convenience without review."),
            _qz("q_d2_01d", "Hacktivist motivation is usually:",
                ["Quiet long dwell only", "Disruption / message", "Backup restore tests", "RTO math"], 1,
                "Visibility and impact, not always stealthy theft."),
        ],
    )

    add(
        "sp_d2_02_vectors_email_identity", "d2_threats", "2.2",
        "Vectors: email and identity", 10,
        ["Phishing", "BEC", "Password Spray", "Legacy Auth", "Attack Surface"],
        [
            ("Vector vs surface", """
                Vector = how they got in. Surface = what they could touch.

                Email / phishing — Invoice.xlsm, BEC vendor-impersonation
                Identity — spray, brute, legacy auth, missing MFA

                Interview: 'The surface I care about first is identity plus email,
                because that is how our lab incidents actually start.'
                """),
            ("Attack surface reduction", """
                Disable macros from the internet, block inbound 3389, disable legacy auth,
                MFA everywhere, shrink local admin.

                Legacy auth that skips MFA is why the CFO inbox rule got created without
                a modern prompt — that is a vector you can remove.
                """),
        ],
        [
            _mc("Password 'Summer2026!' against 30 accounts from one IP. Best name?",
                ["Password spray — one password, many users", "Pass-the-hash from a DC",
                 "Benign Defender scan", "Only brute against one UPN"], 0,
                "Breadth across accounts.",
                "Spray = many users / one password / usually one source."),
            _mc("Inbox rule CFO → Gmail via legacy auth. Primary vectors?",
                ["Only physical USB", "Email/identity path with weak auth protocol",
                 "Only VLAN mislabel", "Printer SNMP"], 1,
                "Mail + auth debt.",
                "BEC collection rides identity and mailbox features."),
            _mc("Best surface shrink for Invoice.xlsm macros?",
                ["Open more SMTP relay", "Block internet macros / ASR Office→script + user training",
                 "Disable all logging", "Trust all attachments from finance"], 1,
                "Remove the execution path.",
                "Mail + endpoint controls beat 'be careful' alone."),
        ],
        [
            _qz("q_d2_02a", "Spray vs brute — spray is:",
                ["One user, many passwords", "One password (or few), many users",
                 "Only USB", "Only DNS"], 1,
                "Breadth vs depth."),
            _qz("q_d2_02b", "Legacy auth is dangerous because:",
                ["It always encrypts better", "It often bypasses modern MFA/CA prompts",
                 "It deletes SIEM", "It is a physical control"], 1,
                "Protocol debt skips controls."),
            _qz("q_d2_02c", "BEC vendor-impersonation primarily uses which vector?",
                ["Email / social", "Only cage keys", "Only NIDS signatures", "RPO"], 0,
                "People + mail."),
            _qz("q_d2_02d", "Attack surface reduction example:",
                ["Expose more RDP", "Disable legacy auth and require MFA",
                 "Delete change tickets", "Turn off EDR"], 1,
                "Remove paths attackers love."),
        ],
    )

    add(
        "sp_d2_03_vectors_remote_supply", "d2_threats", "2.2",
        "Vectors: remote access and supply chain", 9,
        ["RDP", "VPN", "Supply Chain", "Removable Media", "Default Credentials"],
        [
            ("Remote access paths", """
                Remote access — RDP, VPN, vendor jump hosts.
                Exposed RDP to PROD-DC01 from 203.0.113.88 with no VPN is the Boundry
                nightmare path. VPN without MFA is only slightly less bad.

                Default / weak credentials — Summer2026! is the whole spray story.
                """),
            ("Supply chain and media", """
                Supply chain / removable media show up less on Boundry shifts but stay
                on the outline: compromised updater, infected USB in HR, third-party
                MSP with too much standing privilege.

                Talk-track: 'Remote access and identity are my default hypotheses;
                I widen to supply chain when the entry point does not fit email or VPN.'
                """),
        ],
        [
            _mc("ALLOW tcp/3389 from internet to PROD-DC01. Vector class?",
                ["Removable media only", "Remote access / exposed management plane",
                 "Only phishing PDF", "Directive AUP"], 1,
                "Internet RDP is a remote vector.",
                "Management protocols on the open internet are high-value vectors."),
            _mc("Vendor jump with standing domain admin and no review is:",
                ["Great Zero Trust", "Supply-chain / third-party access risk",
                 "Only a physical issue", "Proof of hashing"], 1,
                "Trusted path abuse.",
                "MSP privilege is a supply-chain style surface."),
            _mc("Infected USB dropped at reception is:",
                ["Impossible on the outline", "Removable media vector",
                 "Only SIEM misconfig", "RTO"], 1,
                "Classic physical→endpoint path.",
                "Still teachable even if rare on your shifts."),
        ],
        [
            _qz("q_d2_03a", "Best first fix for internet RDP to a DC?",
                ["More dashboards only", "Remove exposure; VPN/PAM/MFA jump",
                 "Disable logging", "Longer passwords on the attacker"], 1,
                "Close the path."),
            _qz("q_d2_03b", "VPN without MFA is:",
                ["Perfect ZT", "Weaker remote vector control", "Physical only", "PBQ"], 1,
                "Remote access needs strong authn."),
            _qz("q_d2_03c", "Default credentials matter because:",
                ["They decorate SIEM", "Attackers spray known defaults and seasonal passwords",
                 "They improve RPO", "They replace backups"], 1,
                "Predictable secrets."),
            _qz("q_d2_03d", "When do you widen beyond email/VPN hypotheses?",
                ["Never", "When entry evidence does not fit those paths",
                 "Only on Saturdays", "Only if RTO is zero"], 1,
                "Hypothesis-driven triage."),
        ],
    )

    add(
        "sp_d2_04_vulns_misconfig", "d2_threats", "2.3",
        "Vulnerabilities: software and misconfiguration", 10,
        ["Vulnerability", "Misconfiguration", "CVE", "Unpatched", "Insecure Design"],
        [
            ("Types that match tickets", """
                Unpatched application — macro-enabled Office, old VPN client
                Misconfiguration — firewall ALLOW 3389 to a DC; kill switch OFF
                Weak configuration — legacy auth enabled; NTLM fallback
                Default accounts — unused service account creating admins at 03:14
                Insecure design — mailbox forwarding to consumer Gmail with no alert

                CVE vs misconfig: a scanner ticket (Nessus SEC-220) is vuln-management input.
                Exposed RDP may have no CVE at all — it is still a critical vulnerability.
                """),
            ("Zero-day realism", """
                Zero-day — you will not magically 'know' it; you detect behaviour
                (EDR parent/child). Human factors (no travel notice; reused password)
                are vulnerabilities too.
                """),
        ],
        [
            _mc("ALLOW 3389 to DC with no CVE ID. Still a vulnerability?",
                ["No — no CVE means safe", "Yes — misconfiguration / exposure is a vuln class",
                 "Only if printer is down", "Only physical"], 1,
                "Not all vulns are CVEs.",
                "Exposure and misconfig are first-class vulnerability types."),
            _mc("Legacy auth enabled is best typed as:",
                ["Strong design", "Weak / insecure configuration", "Physical control", "RTO"], 1,
                "Protocol setting debt.",
                "Weak configuration enables BEC-style paths."),
            _mc("Mailbox auto-forward to Gmail with no control is:",
                ["Insecure design / missing data control", "Perfect DLP",
                 "Only a CHG success", "Hashing"], 0,
                "Feature without guardrails.",
                "Design that permits silent exfil is a vuln even before malware."),
        ],
        [
            _qz("q_d2_04a", "Nessus finding vs open RDP misconfig:",
                ["Only CVE counts", "Both are vulnerability inputs; misconfig can be worse",
                 "Misconfig is never a vuln", "Ignore both"], 1,
                "Prioritize by exploitability and asset."),
            _qz("q_d2_04b", "Kill switch OFF is:",
                ["Misconfiguration / control gap", "Encryption", "Directive only", "Honeypot"], 0,
                "Expected control not enabled."),
            _qz("q_d2_04c", "Zero-day response starts with:",
                ["Guessing the CVE name", "Behavioural detection and containment",
                 "Opening RDP", "Deleting EDR"], 1,
                "You hunt what it does."),
            _qz("q_d2_04d", "Default service account with admin is:",
                ["Hardening success", "Credential / account hygiene vulnerability",
                 "Only availability", "PBQ font"], 1,
                "Standing privilege + predictable identity."),
        ],
    )

    add(
        "sp_d2_05_vulns_human", "d2_threats", "2.3",
        "Vulnerabilities: human and process gaps", 8,
        ["Social Engineering", "Shadow IT", "Process Gap", "Awareness"],
        [
            ("Humans are in the outline for a reason", """
                Human vulnerabilities: reused seasonal passwords, no travel notice,
                finance paying from a single email without callback, clicking macros
                'because the vendor always sends Excel'.

                Process gaps: no owner on firewall exceptions, no review date on
                vendor VPN accounts, awareness last updated 14 months ago.
                """),
            ("Do not shame — contain and redesign", """
                Interview tone: 'The control failed, including the people process.
                We contain, then we fix training AND the technical path.'
                Shame-the-clicker is a near-miss answer on exams and in jobs.
                """),
        ],
        [
            _mc("CEO travel login without HR note looks like:",
                ["Automatic TP ransomware", "Process gap that forces extra validation",
                 "Proof to open 3389", "Directive CHG for Nessus"], 1,
                "Missing process creates alert debt.",
                "Travel process reduces FP pain and speeds true BEC detection."),
            _mc("Repeat Invoice.xlsm clicks in HR. Vulnerability view?",
                ["Only fire the analyst", "Human + missing technical macro controls",
                 "Only physical doors", "Ignore"], 1,
                "Pair people and tech.",
                "Awareness alone is incomplete if Office→PS still works."),
            _mc("Best response framing for unintentional insider?",
                ["Public shaming", "Contain impact, coach, add technical guardrails",
                 "Disable all accounts forever", "Delete logs"], 1,
                "Ops professionalism.",
                "Treat the risk, not the person's dignity."),
        ],
        [
            _qz("q_d2_05a", "Reused 'Summer2026!' across 30 users is:",
                ["Strong crypto", "Human / password hygiene vulnerability",
                 "Physical only", "RPO"], 1,
                "Predictable human secrets."),
            _qz("q_d2_05b", "No review date on vendor VPN is:",
                ["Process / governance gap", "Perfect ZT", "Hashing", "NIDS"], 0,
                "Standing access without lifecycle."),
            _qz("q_d2_05c", "Callback for payment-change emails reduces:",
                ["Disk encryption need to zero", "BEC / social engineering success",
                 "Need for SIEM", "RTO to zero automatically"], 1,
                "Process control on finance."),
            _qz("q_d2_05d", "Near-miss answer on human vulns:",
                ["Add ASR + role training", "Only mock the clicker in all-hands",
                 "Disable legacy auth", "MFA everywhere"], 1,
                "Shame is not a control strategy."),
        ],
    )

    # PBQ lessons — identity / BEC / malware
    pbq_spray = {
        "id": "pbq_d2_spray",
        "kind": "pick",
        "title": "Name the identity pattern",
        "prompt": (
            "SIEM: 30 distinct users, same password failure cluster, one src_ip, 8 minutes. "
            "No 4624 success yet. What is it, and what do you do first?"
        ),
        "choices": [
            {"id": "spray", "text": "Password spray — block/rate-limit source, watch for success, reset hot accounts, escalate"},
            {"id": "brute", "text": "Brute force on one user only — ignore other UPNs"},
            {"id": "fp", "text": "Close FP — many failures always mean CHG scanner"},
            {"id": "rdp", "text": "Open inbound 3389 to investigate live"},
        ],
        "answer": "spray",
        "explain": "Many users / one source / short window = spray. Contain the source and hunt successes.",
    }

    add(
        "sp_d2_06_ioc_identity", "d2_threats", "2.4",
        "Indicators: spray vs brute", 11,
        ["Password Spray", "Brute Force", "Indicator of Compromise", "SigninLogs"],
        [
            ("Smell the pattern", """
                Spray smell: one src_ip, many distinct users, same failure code, short window.
                SPL: event_type=logon_failed earliest=-1h | stats count by src_ip
                (or KQL dcount of UserPrincipalName by IPAddress).

                Brute smell: one user, high failure rate, maybe then 4624 success —
                that success is the pivot. Always hunt the success after the failures.
                """),
            ("Travel vs spray", """
                Impossible travel / travel login: new country + MFA pass is NOT automatic TP.
                Validate with HR / calendar. Frankfurt + conference = FP with a note.
                Frankfurt + no travel + legacy auth + inbox rule = BEC path.
                """),
        ],
        [
            _mc("30 accounts, one IP, one seasonal password, 10 minutes. Pattern?",
                ["Password spray", "Credential stuffing against a single UPN only",
                 "Pass-the-hash", "Benign Defender"], 0,
                "Breadth.", "Spray = many users / one password / usually one source."),
            _mc("47 failures on jsmith, then 4624 success. Priority?",
                ["Ignore success", "Hunt the success session hard — brute may have worked",
                 "Only close as FP", "Open RDP"], 1,
                "Success after failures is the pivot.",
                "Contain and investigate the authenticated session."),
            _mc("ceo@ Frankfurt, MFA pass, HR confirms conference. Best disposition?",
                ["Automatic ransomware TP", "Likely FP with documented travel validation",
                 "Open 3389", "Disable SIEM"], 1,
                "Context.", "Travel + MFA + HR = FP with a note, not blind trust forever."),
        ],
        [
            _qz("q_d2_06a", "Best spray hunt aggregation?",
                ["count by src_ip / dcount users", "Only printer toner", "Delete 4625", "Ignore IPs"], 0,
                "Source breadth."),
            _qz("q_d2_06b", "Brute force signature:",
                ["Many users, one password", "One user, many failures",
                 "Only USB", "Only DNS tunnel"], 1,
                "Depth on one account."),
            _qz("q_d2_06c", "After spray, you must also:",
                ["Never look for 4624/success", "Hunt successful logons from the attacking IP",
                 "Disable accounting", "Trust VPN blindly"], 1,
                "Failures are the smoke; success is the fire."),
            _qz("q_d2_06d", "Travel login with MFA but no HR note:",
                ["Always close FP", "Validate before FP — missing process raises BEC risk",
                 "Open RDP", "Delete SigninLogs"], 1,
                "Process gap."),
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
        "explain": "BEC / mailbox persistence. Contain identity and the rule first; awareness comes after, not instead.",
    }

    add(
        "sp_d2_07_ioc_bec", "d2_threats", "2.4",
        "Indicators: BEC and mailbox collection", 11,
        ["BEC", "Inbox Rule", "Mailbox Forwarding", "Legacy Auth"],
        [
            ("BEC indicator pack", """
                BEC indicators: new inbox rule, external forward, strange mail-client user-agent,
                missing MFA, finance-themed lure, payment-change language.

                Disposition: escalate. This is collection / fraud enablement (MITRE T1114.003
                style thinking), not a travel FP.
                """),
            ("Near-miss", """
                'Close as FP because email is normal business' is how wire fraud happens.
                Validate with finance callback processes after containment.
                """),
        ],
        [
            _mc("CFO forward-all to Gmail, legacy auth, East EU. First fit mitigation?",
                ["Close travel FP", "Revoke sessions, remove rule, reset, escalate BEC",
                 "Only poster", "Open 3389"], 1,
                "Contain mailbox persistence.",
                "Identity + rule first; awareness later."),
            _mc("Why legacy auth matters in this story?",
                ["It forces MFA", "It often skipped the MFA prompt attackers fear",
                 "It encrypts the forward", "It is physical"], 1,
                "Protocol bypass.",
                "Disable legacy auth as eradication, not as a nice-to-have."),
            _mc("Payment-change email in draft after inbox rule — meaning?",
                ["Proof it is CHG-512", "Fraud staging — warn finance, treat as part of BEC",
                 "Only spam", "Ignore"], 1,
                "Business email compromise payoff.",
                "Containment includes stopping the money path."),
        ],
        [
            _qz("q_d2_07a", "External forward-all rule is primarily:",
                ["Availability of toner", "Confidentiality / collection indicator",
                 "RTO metric", "Honeypot"], 1,
                "Mail leaving the tenant."),
            _qz("q_d2_07b", "Best immediate BEC containment?",
                ["Wait overnight", "Revoke sessions + remove rule + reset",
                 "Open RDP", "Disable SIEM"], 1,
                "Kill persistence and sessions."),
            _qz("q_d2_07c", "MITRE-ish technique family for inbox rules:",
                ["Mailbox collection / email collection", "Only physical theft",
                 "Only VLAN", "Only backup"], 0,
                "Collection of mail."),
            _qz("q_d2_07d", "Awareness-only response to confirmed BEC is:",
                ["Complete", "Incomplete — needs technical identity/mail fixes",
                 "Better than containment", "A backout plan"], 1,
                "People + tech."),
        ],
        pbq_bec,
    )

    pbq_ps = {
        "id": "pbq_d2_ps",
        "kind": "pick",
        "title": "Encoded PowerShell next action",
        "prompt": (
            "WS-HR-03 — powershell.exe -enc spawned by excel.exe. Parent Invoice.xlsm from email. "
            "No change ticket. Host still on the LAN. What next?"
        ),
        "choices": [
            {"id": "isolate", "text": "Isolate host, preserve EDR evidence, escalate, hunt mail campaign / hash"},
            {"id": "fp", "text": "Close FP — Excel is approved business software"},
            {"id": "wait", "text": "Leave online and re-check in the morning for encryption notes"},
            {"id": "rdp", "text": "Open internet RDP to watch Task Manager"},
        ],
        "answer": "isolate",
        "explain": "Parent/child + encoded command + email lure = execution chain. Contain first.",
    }

    add(
        "sp_d2_08_ioc_endpoint", "d2_threats", "2.4",
        "Indicators: endpoint and malware execution", 11,
        ["EDR", "PowerShell", "Parent-Child Process", "Obfuscation"],
        [
            ("Encoded PowerShell tell", """
                Encoded PowerShell: parent/child (excel.exe → powershell.exe), -enc,
                unsigned script, network egress after. MITRE T1059.001 thinking.

                Do not decode the blob on the hotspot laptop — isolate, preserve, escalate.
                """),
            ("Approved app near-miss", """
                'Excel is approved' is the near-miss that gets hosts encrypted.
                Approved parents launching suspicious children are still malicious.
                """),
        ],
        [
            _mc("excel.exe → powershell.exe -enc from Invoice.xlsm. Best read?",
                ["Approved Office — close FP", "Suspicious parent/child + encoded command — isolate",
                 "Proof DC already ransomware'd", "Authorized JUMP-01 scan"], 1,
                "Parent image + encoded command.",
                "Malware execution path. Isolation matches the mitigation."),
            _mc("Wrong first IR move after confirmed -enc chain?",
                ["Isolate and preserve", "Leave on LAN to see if files encrypt overnight",
                 "Escalate", "Pull EDR tree into ticket"], 1,
                "Containment before curiosity.",
                "Watching ransomware finish is not analysis."),
            _mc("Why not decode -enc on your admin laptop immediately?",
                ["Because Base64 is encryption", "Preserve evidence; avoid contaminating analyst workstation",
                 "Because EDR forbids tickets", "Because CHG requires it"], 1,
                "Ops hygiene.",
                "Isolate victim, use proper analysis path."),
        ],
        [
            _qz("q_d2_08a", "Parent/child excel→powershell is valuable because:",
                ["It proves CHG", "It shows execution chain, not just a noisy script host",
                 "It opens RDP", "It sets RPO"], 1,
                "Context of launch."),
            _qz("q_d2_08b", "-enc indicates:",
                ["Guaranteed AES confidentiality", "Likely obfuscation/tradecraft",
                 "Digital signature", "Physical access"], 1,
                "Encoding ≠ encryption."),
            _qz("q_d2_08c", "First containment for endpoint malware execution:",
                ["Ignore", "Isolate host / network contain", "Disable all MFA", "Delete SIEM"], 1,
                "Stop spread."),
            _qz("q_d2_08d", "'Excel is approved' as close reason is:",
                ["Solid", "Near-miss — approved apps can launch malicious children",
                 "Required by ZT", "A backout"], 1,
                "Living-off-the-land."),
        ],
        pbq_ps,
    )

    add(
        "sp_d2_09_ioc_network", "d2_threats", "2.4",
        "Indicators: network and exposure", 10,
        ["Firewall", "RDP", "Lateral Movement", "C2", "Beaconing"],
        [
            ("Exposure vs probe", """
                RDP from internet: firewall ALLOW on 3389 to a prod identity store.
                Even one successful path beats a thousand DROPs on 445.

                Commodity SMB/RDP probes that are DROP: note IOC, confirm no internal
                follow-on. Do not page like domain compromise.
                """),
            ("Lateral and C2 smells", """
                Lateral movement: unusual admin shares, remote services, sudden auth
                from WS-HR-03 to PROD-DC01 after a phishing click.

                C2 / beaconing: steady odd egress, rare ports, newly staged binaries
                talking out. Pair with EDR — firewall alone is incomplete.
                """),
        ],
        [
            _mc("Internet SMB 445 DROP burst, no internal lateral. Take?",
                ["Rebuild every host", "Commodity probe; perimeter deny held — note IOC",
                 "Same urgency as ALLOW 3389 on DC", "Proof of CFO rules"], 1,
                "DROP + no lateral.",
                "Failed probe ≠ exposed RDP incident class."),
            _mc("ALLOW 3389 from 203.0.113.88 → PROD-DC01. Severity mindset?",
                ["INFO only", "Critical exposure / likely incident path — remove and investigate",
                 "Ignore if no CVE", "Only awareness"], 1,
                "Path to crown jewel.",
                "Identity store + internet RDP is emergency architecture + IR."),
            _mc("After phishing, auth from HR PC to DC admin shares suggests:",
                ["Normal toner alert", "Possible lateral movement — escalate and contain",
                 "Only CHG success", "Hashing"], 1,
                "Post-compromise movement.",
                "Hunt and isolate the path."),
        ],
        [
            _qz("q_d2_09a", "Why is ALLOW worse than DROP for the same port?",
                ["Fonts", "ALLOW means the path worked or is open; DROP means perimeter held",
                 "DROP always means ransomware", "ALLOW is always CHG"], 1,
                "Outcome of the control."),
            _qz("q_d2_09b", "Beaconing is roughly:",
                ["Steady suspicious egress / callback pattern", "Only badge logs",
                 "Only AUP text", "RTO"], 0,
                "C2 rhythm."),
            _qz("q_d2_09c", "Best pairing for network IOC triage:",
                ["Firewall only forever", "Firewall + EDR/identity context",
                 "Delete logs", "Open more ports"], 1,
                "Corroborate."),
            _qz("q_d2_09d", "Internet RDP to DC with no VPN is:",
                ["Zero Trust success", "Critical network exposure indicator",
                 "Only a managerial poster", "Backup proof"], 1,
                "Architecture failure visible in firewall."),
        ],
    )

    add(
        "sp_d2_10_mitigate_identity", "d2_threats", "2.5",
        "Mitigations: identity and email", 10,
        ["MFA", "Conditional Access", "Legacy Auth", "DLP", "Password Policy"],
        [
            ("Match mitigation to pattern", """
                Spray → MFA, lockout/smart lockout, block bad IPs, password hygiene,
                detect successes fast.

                BEC → revoke sessions, remove rules, disable legacy auth, DLP/external
                forward controls, CA for risky sign-ins, finance callback process.

                Do not pick 'more dashboards' as the primary mitigation when the path
                is still open.
                """),
            ("Purpose of the technique", """
                Exam language: explain the purpose. Ops language: say what it stops.
                MFA purpose: raise authentication strength so spray/stuffing fails more.
                Disabling legacy auth purpose: force modern auth that can demand MFA/CA.
                """),
        ],
        [
            _mc("Primary mitigation purpose of MFA against spray?",
                ["Faster RDP", "Make stolen/guessed passwords insufficient alone",
                 "Delete accounting", "Replace backups"], 1,
                "Second factor.",
                "MFA raises the cost of password-only attacks."),
            _mc("Best technical mitigation pair for BEC forward rules?",
                ["Only posters", "Disable legacy auth + block/alert external forwards (DLP/CA)",
                 "Open 3389", "Turn off mailbox audit"], 1,
                "Close the protocol and the exfil feature.",
                "Tech + process."),
            _mc("Mitigation that does NOT fit confirmed malware execution?",
                ["Isolate host", "Leave host up to observe encryption",
                 "Hunt hash in mail", "ASR Office→script"], 1,
                "Containment is the fit.",
                "Observation without isolate is the wrong mitigation."),
        ],
        [
            _qz("q_d2_10a", "Purpose of disabling legacy auth:",
                ["Speed toner alerts", "Force modern auth paths that support MFA/CA",
                 "Open RDP", "Remove SIEM"], 1,
                "Close weak protocols."),
            _qz("q_d2_10b", "External forward block is mainly:",
                ["Availability of Wi-Fi", "Data exfil / confidentiality mitigation",
                 "Physical cage", "RPO number"], 1,
                "Stop mail leaving."),
            _qz("q_d2_10c", "Smart lockout purpose:",
                ["Punish users only", "Slow spray/brute while limiting collateral",
                 "Disable EDR", "Replace IR"], 1,
                "Rate-limit attacks."),
            _qz("q_d2_10d", "Picking 'awareness poster only' for open RDP is:",
                ["Correct primary mitigation", "Wrong — remove the exposure",
                 "Required ZT", "A hash"], 1,
                "Match control to vector."),
        ],
    )

    add(
        "sp_d2_11_mitigate_segment", "d2_threats", "2.5",
        "Mitigations: segmentation, hardening, monitoring", 10,
        ["Segmentation", "Hardening", "Isolation", "EDR", "Patching"],
        [
            ("Enterprise mitigations that show up in Boundry", """
                Segmentation / deny 3389 — shrink blast radius and remove exposure
                Hardening / ASR — stop Office from launching script hosts
                Patching — reduce exploitability of known vulns
                Isolation — corrective containment when execution already happened
                Monitoring (SIEM/EDR) — detective layer; necessary but not sufficient alone
                """),
            ("Pick the fit", """
                Exposed RDP → remove path / VPN+PAM (not 'add another dashboard')
                Macro malware → ASR + mail controls + isolate if already running
                Unpatched VPN → patch / replace client, then monitor

                Interview: 'Mitigation purpose is to interrupt the kill chain at the
                cheapest reliable step — preferably before execution.'
                """),
        ],
        [
            _mc("Best mitigation for internet RDP to DC?",
                ["More SIEM panels only", "Remove internet RDP; VPN+MFA+jump/PAM; segment",
                 "Move DC to HR Wi-Fi", "Disable logging"], 1,
                "Path removal.",
                "Architecture fix beats detective-only."),
            _mc("Purpose of host isolation after malware execution?",
                ["Punish the user", "Corrective — stop spread / reduce impact",
                 "Replace MFA", "Approve CHG"], 1,
                "Containment.",
                "Isolation is corrective mitigation."),
            _mc("Monitoring without removing open 3389 means:",
                ["Fully mitigated", "Detective coverage on an unfixed preventive failure",
                 "Physical fix", "Encryption complete"], 1,
                "Detect ≠ prevent.",
                "You still need the preventive fix."),
        ],
        [
            _qz("q_d2_11a", "Segmentation purpose:",
                ["Pretty VLANs only", "Limit blast radius / separate trust tiers",
                 "Delete logs", "Disable MFA"], 1,
                "Contain movement."),
            _qz("q_d2_11b", "ASR blocking Office→child script is:",
                ["Hardening / preventive endpoint mitigation", "Only managerial poster",
                 "RTO", "Honeypot"], 0,
                "Stop living-off-the-land."),
            _qz("q_d2_11c", "Patching purpose:",
                ["Remove known exploit paths", "Open more ports", "Replace IR docs", "Shame users"], 0,
                "Reduce vulnerability window."),
            _qz("q_d2_11d", "When is isolation the right mitigation?",
                ["Before any alert ever", "After suspected/confirmed execution on a host",
                 "Instead of tickets forever", "Only for printers"], 1,
                "Corrective timing."),
        ],
    )
