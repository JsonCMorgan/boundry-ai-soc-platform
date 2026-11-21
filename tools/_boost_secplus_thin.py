"""Append denser desk-clue blocks to thinner D3–D5 lesson bodies in generators."""
from __future__ import annotations

import re
from pathlib import Path

TOOLS = Path(__file__).resolve().parent

# Extra ~120-160 words keyed by lesson id, inserted before "How to answer on the exam:"
BOOST: dict[str, str] = {
    "sp_d3_03_infra_network": """
More desk clues:
  - Prefer explicit source/destination/port on crown-jewel ALLOWs. ANY/ANY is a finding.
  - Admin paths: VPN (UDP 500/4500 or TLS VPN) + jump/PAM beats inbound TCP 3389.
  - East-west: deny user VLANs to DC admin ports by default; allow only brokers.
  - When SIEM shows scanner noise, still confirm no unexpected ALLOW appeared beside it.
""",
    "sp_d3_04_infra_endpoint_cloud": """
More desk clues:
  - Endpoint: EDR health, ASR rules, local admin count, BitLocker status, patch age.
  - Cloud control plane: MFA on Global Admin / Owner roles, PIM/JIT if available, no public storage with sensitive exports.
  - Drift check: compare baseline GPO/Intune/ASR to what HR images actually run.
  - Secrets in repos and chat are infrastructure findings, not style notes.
""",
    "sp_d3_05_data_states": """
More desk clues:
  - In transit check: browser TLS, SMTP/TLS, VPN. Cleartext login pages fail this state.
  - At rest check: BitLocker/FileVault, encrypted backups, encrypted cloud objects.
  - In use check: who can open the file now (ACL/DLP/rights), not only disk encryption.
  - Exam near-miss: answering BitLocker when the story is an HTTP password form.
""",
    "sp_d3_06_dlp_encryption": """
More desk clues:
  - TLS does not stop a valid session from creating an external forward rule.
  - BitLocker does not stop upload from an unlocked logged-in laptop.
  - DLP/forward controls and encryption answer different failure modes. Often you need both.
  - Keys beside ciphertext (backup key on the same share) fail "appropriate use."
""",
    "sp_d3_07_resilience_ha": """
More desk clues:
  - Name the single point of failure: one VPN concentrator, one DNS, one MFA provider, one jump host.
  - HA pairs that share the same ransomware-accessible backup identity still fail recovery.
  - Test failover under load assumptions. Untested failover is documentation, not control.
  - Break-glass accounts need monitoring so resilience does not become a backdoor.
""",
    "sp_d3_08_backup_rto": """
More desk clues:
  - Nightly-only jobs fail a 15-minute RPO. Match frequency to the RPO number.
  - Separate backup identity from Domain Admin. Monitor the recovery plane.
  - Encrypt backups; keep keys off the same share as the ciphertext.
  - If restore takes 18h and RTO is 4h, you failed RTO. Fix process or site readiness.
""",
    "sp_d3_09_continuity_testing": """
More desk clues:
  - Tabletop finds decision/people gaps. Technical failover finds restore/path gaps. You need both over time.
  - Update contact trees after every exercise. Stale on-call lists fail first.
  - Include critical vendors/MSPs when they sit on the restore or comms path.
  - After-action items need owner + due date or the exercise was theater.
""",
    "sp_d4_01_harden_compute": """
More desk clues:
  - Verify ASR actually blocks Office→script on a test host after deploy.
  - Jump hosts: stricter logging, no email browsing, MFA, limited tools.
  - Containers: minimal base image, non-root, scanned, secrets not baked in.
  - If excel→powershell still works, the harden ticket is not done.
""",
    "sp_d4_02_harden_network_app": """
More desk clues:
  - Management plane exposure beats app CVE arguments when 3389/22 face the internet.
  - App defaults: remove /admin vendor passwords, unused verbs, sample pages.
  - Put TLS on admin UIs. Rate-limit login endpoints that get sprayed.
  - WAF helps HTTP classes. It does not close non-HTTP management ports.
""",
    "sp_d4_03_asset_management": """
More desk clues:
  - Inventory must include service accounts and VPN objects, not only laptops.
  - Offboard day-0: disable account, revoke MFA devices, pull groups, wipe/return device.
  - Unknown privileged account at 03:14 is asset + integrity + IR in one alert.
  - Shadow IT appears where inventory and ownership are weak.
""",
    "sp_d4_04_vuln_lifecycle": """
More desk clues:
  - Prioritize with asset value: medium CVE on a DC can outrank critical on a lab printer.
  - Misconfig without CVE still enters discover→remediate→verify.
  - Exceptions need compensating control + owner + review date.
  - Rescan is the verify step. Green tickets without rescan are incomplete.
""",
    "sp_d4_05_vuln_scan_context": """
More desk clues:
  - Match scanner host/IP to CHG before paging APT on JUMP-01.
  - Credentialed scans need protected scanner credentials and least privilege.
  - Fragile OT: approved methods, windows, stop conditions.
  - Allow-list the scanner in the same ticket as the firewall/SIEM exception.
""",
    "sp_d4_06_alerting_queue": """
More desk clues:
  - Priority inputs: severity, asset tier, whether a path is open, whether execution already happened.
  - Validate with the right source in minutes, not with dashboard vibes.
  - Live malware/BEC: contain before writing the novel.
  - Tune noise with CHG-linked exceptions. Do not disable crown-jewel detections.
""",
    "sp_d4_07_siem_tools": """
More desk clues:
  - Identity pattern → SigninLogs/462x/SIEM aggregate.
  - Execution chain → EDR process tree.
  - Path open/blocked → firewall/VPN.
  - Mailbox persistence → mailbox audit / unified audit.
  - Wrong-tool answers are classic near-misses on the exam.
""",
    "sp_d4_08_tune_capabilities": """
More desk clues:
  - Narrow exclusions (host/identity/time window) beat /8 forever.
  - Add detections from real incidents (external forward rule creation, Office→PS).
  - Change-control detection edits like production code: reason, review, rollback.
  - Re-test with a known true-positive case after tuning.
""",
    "sp_d4_09_iam_ops": """
More desk clues:
  - Joiner/mover/leaver SLAs beat quarterly cleanup heroes.
  - Standing Global Admin / Domain Admin for daily mail is an ops failure.
  - Disable legacy auth and monitor for breakages with a backout.
  - Access reviews on privileged roles are IAM ops, not optional paperwork.
""",
    "sp_d4_10_automation_soar": """
More desk clues:
  - Automate enrich, ticket fields, notifications first.
  - Gate disable-user / firewall-block / isolate behind confidence + human approve when impact is high.
  - Idempotent playbooks with rate limits prevent ticket storms.
  - Log every automated action for audit and IR timelines.
""",
    "sp_d4_11_ir_phases": """
More desk clues:
  - Containment examples: isolate host, revoke sessions, block hash/IP, disable rule.
  - Eradication examples: remove persistence, disable legacy auth, delete malicious inbox rule.
  - Recovery examples: reimage, restore, re-enable with heightened monitoring.
  - Preparation failures show up as missing isolate authority or dead tooling.
""",
    "sp_d4_12_ir_comms_docs": """
More desk clues:
  - Audience map: finance for payment risk, legal/leadership for material incidents, users for safety notices via approved channels.
  - Ticket timeline fields: detect, contain, eradicate, recover.
  - Preserve EDR exports/hashes before casual reimage when analysis still matters.
  - Do not paste live malware or secrets into open chat.
""",
    "sp_d4_13_sources_identity": """
More desk clues:
  - Spray: aggregate failures by IP + distinct users, then hunt 4624/success.
  - BEC: mailbox audit for New-InboxRule / forward + SigninLogs client app/legacy flags.
  - Privilege: directory audit for group adds / new admin users.
  - Always write the time window and timezone into the ticket.
""",
    "sp_d4_14_sources_endpoint_net": """
More desk clues:
  - Endpoint pack: parent/child, command line, hash, user, path, egress.
  - Network pack: ALLOW/DROP, src/dst/port, VPN user mapping, DNS query name.
  - If EDR is missing on a crown jewel, say the blind spot and lean on identity/network harder.
  - Never open more inbound management ports to "investigate live."
""",
    "sp_d4_15_investigation_pack": """
More desk clues:
  - Minimum pack: summary, timeline, sources, IOCs, actions, disposition, next owner.
  - Include negative findings ("no successful 4624 from attacking IP").
  - Link CHG numbers for FP scanner cases so the next shift does not re-page.
  - Redact secrets before wide sharing; keep full evidence in the controlled ticket.
""",
    "sp_d5_01_governance_policy": """
More desk clues:
  - Say/do test: policy text vs live Entra/firewall/EDR config.
  - AUP without standards/procedures cannot stop macros alone.
  - Ownership and review cadence keep documents from rotting.
  - Exceptions must reference the standard they waive.
""",
    "sp_d5_02_roles_exceptions": """
More desk clues:
  - Exception record fields: what, why, compensating control, approver, owner, expiry.
  - SOC can recommend; business/system owner accepts residual risk.
  - High-risk paths (internet RDP to DC) should rarely clear exception review.
  - RACI fails when Accountable is "TBD" or "the cloud."
""",
    "sp_d5_03_risk_process": """
More desk clues:
  - Inherent vs residual: before controls vs after controls.
  - Qualitative ratings are fine on Security+ if likelihood and impact are reasoned.
  - Risk register is where SOC leftovers become program work.
  - Appetite is leadership's band; analysts escalate facts that exceed it.
""",
    "sp_d5_04_risk_treatment": """
More desk clues:
  - Mitigate examples: turn kill switch ON, disable legacy auth, remove 3389.
  - Accept examples: low lab risk with owner/date, never silent DC exposure.
  - Transfer examples: insurance/contracts still need operational controls.
  - Avoid examples: do not offer internet RDP to identity stores at all.
""",
    "sp_d5_05_third_party": """
More desk clues:
  - Tier vendors by data sensitivity and standing access depth.
  - Review MSP/VPN/admin accounts on a calendar, not only at purchase.
  - Offboard integrations: keys, apps, groups, SSO, shared mailboxes.
  - Their breach notice clause matters when their incident becomes yours.
""",
    "sp_d5_06_compliance": """
More desk clues:
  - Map each requirement to a control owner and evidence location.
  - Retention/logging rules often help investigations and audits together.
  - Passing last year's audit does not bless this week's open RDP.
  - Privacy rules shape how investigation packs are shared.
""",
    "sp_d5_07_audits_assessments": """
More desk clues:
  - Finding closure needs fix + evidence + owner sign-off, not a promise.
  - Check scope exclusions that hide crown jewels.
  - Self-assessment helps; independent audit claims need real independence.
  - Vendor SOC reports inform diligence; they do not replace access reviews.
""",
    "sp_d5_08_pen_vs_vuln": """
More desk clues:
  - Scan cadence can be weekly/monthly. Pen tests are usually deeper and less frequent.
  - ROE and authorization letters are mandatory before offensive testing.
  - Both produce findings that enter the same remediation/risk process.
  - A clean scan does not prove no exploitable business path exists.
""",
    "sp_d5_09_awareness_basics": """
More desk clues:
  - Measure report quality and time-to-report, not only completion checkmarks.
  - Pair every awareness theme with a technical control (ASR, MFA, DLP).
  - Keep reporting frictionless: button/mailbox and a thank-you response.
  - Shame culture suppresses the human sensor network.
""",
    "sp_d5_10_awareness_role": """
More desk clues:
  - Finance: callback drills and payment-change verification.
  - Helpdesk: identity verification before resets; MFA fatigue resistance.
  - Admins: no daily email on privileged accounts; tool hygiene.
  - Track metrics by role so exec/finance risk is not hidden in org averages.
""",
    "sp_d5_11_oversight_tieback": """
More desk clues:
  - After IR, name the program object that changes: standard, exception, risk row, training, vendor access.
  - Metrics that matter: repeat incident rate, aged exceptions, privileged training completion.
  - Unowned "next steps" in tickets become next quarter's identical alert.
  - Oversight talk-track beats "we told users to be careful."
""",
    # D2 desk-clue boosts (keep after thick pack rewrite)
    "sp_d2_05_vulns_human": """
More desk clues:
  - Shadow IT smell: personal forward, rogue VPN, unsanctioned SaaS with company data.
  - Exception without expiry is a standing vulnerability. Demand owner + review date.
  - Reused seasonal passwords raise spray hit rate across many users.
  - Pair every awareness theme with a technical guardrail (ASR, MFA, DLP, callback).
""",
    "sp_d2_07_ioc_bec": """
More desk clues:
  - Mailbox audit / UAL: look for New-InboxRule, Set-Mailbox forwarding, unusual client apps.
  - SigninLogs: legacy vs modern, MFA detail, location, impossible travel context.
  - Finance path: payment-change language in drafts/sent items after rule creation.
  - Eradication backlog after contain: disable legacy auth, forward controls, CA hardening.
""",
    "sp_d2_08_ioc_endpoint": """
More desk clues:
  - Capture: process tree, command line, hash, user, path, network connects.
  - Isolate first on confirmed hostile child; then hunt the campaign hash in mail/EDR.
  - Living-off-the-land: powershell, wscript, mshta, rundll32 as children of Office.
  - Encoding (-enc) is obfuscation. Say it. Do not call it encryption.
""",
    "sp_d2_09_ioc_network": """
More desk clues:
  - Ports: 3389 RDP, 22 SSH, 445 SMB, VPN often UDP 500/4500 or TLS VPN.
  - Beaconing: regular callback rhythm to a rare destination after phishing/macro.
  - Pair ALLOW rows with VPN user mapping and EDR when asset tier is high.
  - Never open more inbound management ports to "investigate live."
""",
    "sp_d2_10_mitigate_identity": """
More desk clues:
  - After spray: hunt successful logons from the attacking IP before closing.
  - Legacy auth often skips MFA. That is why disable-legacy pairs with BEC fixes.
  - CA examples: require MFA for admins, block legacy, require compliant device.
  - Detect-only panels are incomplete while the identity path stays open.
""",
    "sp_d2_11_mitigate_segment": """
More desk clues:
  - Jump/PAM brokers admin; deny user VLANs to DC admin ports by default.
  - Isolation timing: after suspected/confirmed execution on the host.
  - Patching removes known exploitability; segmentation removes free blast radius.
  - Monitoring without removing open 3389 is detective coverage on a preventive miss.
""",
    "sp_d3_02_zero_trust_arch": """
More desk clues:
  - CA examples: MFA for admins, block legacy auth, compliant device for sensitive apps.
  - Microsegmentation: deny HR VLAN to DC:3389/445 admin paths by default.
  - Flat network after phishing makes lateral movement trivial.
  - ZT sticker with internet RDP still open is architecture theater.
""",
}

INSERT_BEFORE = "How to answer on the exam:"


def boost_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    n = 0
    for lid, block in BOOST.items():
        if f'"{lid}"' not in text:
            continue
        # Only insert once per lesson: find lesson region roughly
        start = text.find(f'"{lid}"')
        if start < 0:
            continue
        # find next lesson id or end
        nxt = re.search(r'\n\s+add\(\s*\n\s+"sp_', text[start + 10 :])
        end = start + 10 + nxt.start() if nxt else len(text)
        region = text[start:end]
        if "More desk clues:" in region:
            continue
        if INSERT_BEFORE not in region:
            print("skip no insert point", lid)
            continue
        # Insert boost before first How to answer in this lesson region
        # Prefer the first section's How to answer
        boost = "\n".join(
            "                " + ln if ln.strip() else ""
            for ln in block.strip("\n").splitlines()
        )
        new_region = region.replace(
            INSERT_BEFORE,
            boost + "\n\n                " + INSERT_BEFORE,
            1,
        )
        text = text[:start] + new_region + text[end:]
        n += 1
        print("boosted", lid)
    path.write_text(text, encoding="utf-8")
    return n


def main() -> None:
    total = 0
    for name in ("gen_secplus_d2b.py", "gen_secplus_d3.py", "gen_secplus_d4.py", "gen_secplus_d5.py"):
        total += boost_file(TOOLS / name)
    print("boosted lessons:", total)


if __name__ == "__main__":
    main()
