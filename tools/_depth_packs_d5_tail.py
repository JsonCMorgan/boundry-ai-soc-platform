"""Tail packs for Domain 5 lessons 08-11. Appended by apply script or imported."""
from __future__ import annotations

# This module is executed via runpy after DEPTH/put/body exist in caller globals,
# or imported only after put/body are available. Prefer: exec from apply script.

TAIL_SOURCE = r'''
put(
    "sp_d5_08_pen_vs_vuln",
    17,
    [
        (
            "Pen test vs vuln scan",
            body(
                orient=(
                    "A vulnerability scan finds known weaknesses broadly. A penetration test "
                    "simulates attacker techniques to prove exploitable paths, usually with a "
                    "defined scope and rules of engagement."
                ),
                work=(
                    "weekly Nessus finds missing patches. An annual pen test proves whether "
                    "an open path can reach the DC. Different questions, different outputs."
                ),
                formal="penetration testing versus vulnerability scanning.",
                beats=(
                    "Contrast:\n"
                    "  Vuln scan → breadth, known issues, frequent, lower impact if configured safely\n"
                    "  Pen test → depth, exploitation/proof, scoped, higher skill/cost\n"
                    "  Red team → broader adversary simulation (related idea)\n"
                    "  Bug bounty → external researcher program (related idea)"
                ),
                tech=(
                    "  - Scans need authorization and safety (Domain 4 overlap)\n"
                    "  - Pen tests need ROE, contacts, and stop conditions\n"
                    "  - Neither replaces patching or path removal"
                ),
                worked=(
                    "Open RDP may show on a scan as exposure/misconfig and also be a pen-test "
                    "finding if exploited. Scan frequency is higher; pen tests are deeper proofs."
                ),
                how=(
                    "  1. Ask if the question wants breadth discovery or exploit proof.\n"
                    "  2. Match scan vs pen test.\n"
                    "  3. Keep authorization in view."
                ),
                trap="calling a vuln scan a pen test because it has a red logo, or skipping fixes because a pen test is scheduled next year.",
                remember="Scan finds. Pen test proves. Both need remediation owners.",
            ),
        ),
        (
            "Rules of engagement",
            body(
                work="tester starts attacking prod payroll at noon with no window or contact.",
                formal="authorization and ROE for offensive assessments.",
                beats=(
                    "ROE beats: scope, timing, contacts, data handling, stop conditions, get-out-of-jail letter."
                ),
                tech=(
                    "  - Unauthorized testing is illegal and an incident\n"
                    "  - Findings still need treatment like other risks"
                ),
                worked=(
                    "No ROE = stop. Good programs treat findings through the risk register."
                ),
                how=(
                    "  1. Demand authorization/scope.\n"
                    "  2. Separate scan vs exploit depth.\n"
                    "  3. Route findings to owners."
                ),
                trap="equating any scanner output with 'we were pen tested.'",
                remember="No authorization, no test. Findings still need owners.",
            ),
        ),
    ],
)

put(
    "sp_d5_09_awareness_basics",
    16,
    [
        (
            "Awareness that changes behavior",
            body(
                orient=(
                    "Security awareness teaches people how to recognize and report risks. It is "
                    "a control layer, not a substitute for technical guardrails."
                ),
                work=(
                    "phishing simulations, short role tips for finance callbacks, and reporting "
                    "paths that do not shame accidental clicks."
                ),
                formal="security awareness program basics.",
                beats=(
                    "Awareness beats:\n"
                    "  1. Relevant content (phishing, BEC, USB, travel)\n"
                    "  2. Frequency that sticks\n"
                    "  3. Easy reporting\n"
                    "  4. Metrics (report rate, click trends) without shame culture\n"
                    "  5. Pair with technical ASR/MFA/DLP"
                ),
                tech=(
                    "  - Poster-only after confirmed BEC is incomplete\n"
                    "  - Simulations should train, not humiliate\n"
                    "  - Track completion and real report quality"
                ),
                worked=(
                    "AUP helps set expectations after macro incidents, but ASR still required. "
                    "Awareness last updated 14 months ago is a process gap."
                ),
                how=(
                    "  1. Prefer awareness + technical pairing.\n"
                    "  2. Reject shame-only answers.\n"
                    "  3. Look for reporting path clarity."
                ),
                trap="annual boring slideshow as the only control for active phishing.",
                remember="Awareness steers humans. Technical controls still close paths.",
            ),
        ),
        (
            "Reporting culture",
            body(
                work="user almost clicks, then reports. Analyst thanks them and checks the campaign.",
                formal="positive reporting culture as part of awareness effectiveness.",
                beats=(
                    "Good culture: fast thank-you, no public shaming, rapid block of related IOCs."
                ),
                tech=(
                    "  - Report button / dedicated mailbox\n"
                    "  - Feed reports into detections"
                ),
                worked=(
                    "Punishing reporters kills the detection source you need."
                ),
                how=(
                    "  1. Reward reporting.\n"
                    "  2. Fix paths.\n"
                    "  3. Keep training fresh."
                ),
                trap="mocking the clicker in all-hands.",
                remember="People report more when it is safe to report.",
            ),
        ),
    ],
)

put(
    "sp_d5_10_awareness_role",
    16,
    [
        (
            "Role-based awareness",
            body(
                orient="Different jobs need different awareness. Finance is not HR is not admins.",
                work=(
                    "finance gets BEC callback drills. Admins get phishing-resistant MFA and "
                    "privileged account hygiene. Developers get secrets-in-git training."
                ),
                formal="role-based security awareness and privileged-user training.",
                beats=(
                    "Role map:\n"
                    "  Finance → BEC / payment change verification\n"
                    "  Executives → high-value targeting, travel process\n"
                    "  Admins → privileged phishing, tool hygiene\n"
                    "  All staff → phishing basics + reporting"
                ),
                tech=(
                    "  - Privileged users are higher-value targets\n"
                    "  - Role training pairs with IAM controls\n"
                    "  - Measure by role, not only org-wide averages"
                ),
                worked=(
                    "Generic annual training alone fails finance BEC scenarios. "
                    "Add callback drills + technical forward controls."
                ),
                how=(
                    "  1. Match training to role risk.\n"
                    "  2. Pair with technical controls.\n"
                    "  3. Keep privileged training stricter."
                ),
                trap="one identical slideshow for every role forever.",
                remember="Train the job people actually do.",
            ),
        ),
        (
            "Privileged targets",
            body(
                work="helpdesk and domain admins receive convincing MFA fatigue or helpdesk impersonation lures.",
                formal="elevated awareness for privileged and helpdesk roles.",
                beats=(
                    "Extra topics: MFA fatigue, vishing, password reset verification, out-of-band checks."
                ),
                tech=(
                    "  - Number matching / phishing-resistant MFA reduces fatigue abuse\n"
                    "  - Helpdesk verification procedures are awareness + procedure"
                ),
                worked=(
                    "Helpdesk resetting a VIP without verification is an awareness and process miss."
                ),
                how=(
                    "  1. Identify privileged audience.\n"
                    "  2. Prefer stricter process answers.\n"
                    "  3. Combine with IAM tech."
                ),
                trap="assuming admins already know and skipping their training.",
                remember="Privileged users need privileged training.",
            ),
        ),
    ],
)

put(
    "sp_d5_11_oversight_tieback",
    17,
    [
        (
            "Tie oversight back to the ticket",
            body(
                orient=(
                    "Domain 5 closes the loop: governance, risk, vendors, compliance, audits, "
                    "and awareness exist so tomorrow's ticket is less likely. Oversight without "
                    "ops feedback is theater."
                ),
                work=(
                    "after BEC you disable legacy auth (ops), update the standard (governance), "
                    "record residual risk (risk), brief finance (awareness), and evidence the "
                    "change for audit."
                ),
                formal="tying program oversight actions back to operational incidents.",
                beats=(
                    "Tieback loop:\n"
                    "  1. Incident / finding happens\n"
                    "  2. Contain in ops (Domain 4)\n"
                    "  3. Update control / policy / exception (Domain 5)\n"
                    "  4. Assign residual risk owner\n"
                    "  5. Train the affected role\n"
                    "  6. Evidence for audit"
                ),
                tech=(
                    "  - Portfolio What/Why/Disposition/Next is an oversight-friendly artifact\n"
                    "  - Unowned follow-ups return as repeat incidents\n"
                    "  - Vendors implicated in the path get access reviews"
                ),
                worked=(
                    "Repeat Invoice.xlsm without ASR update + role training means oversight failed "
                    "to close the loop even if each ticket was resolved."
                ),
                how=(
                    "  1. After the firefight, ask what program object changes.\n"
                    "  2. Name owner and date.\n"
                    "  3. Prefer loop-closing answers over one-off heroics."
                ),
                trap="closing incidents forever with no policy/risk/awareness follow-through.",
                remember="Owner, treatment, vendor, awareness. Close the loop.",
            ),
        ),
        (
            "Program talk-track",
            body(
                work="interview: how do you prevent the same BEC next quarter?",
                formal="program-level prevention language after IR.",
                beats=(
                    "Talk-track: technical eradicate + standard update + finance drill + residual risk review + evidence."
                ),
                tech=(
                    "  - Metrics: repeat incident rate, exception aging, training completion by role\n"
                    "  - Escalation path into leadership when appetite is exceeded"
                ),
                worked=(
                    "Strong answer names disable legacy auth, forward controls, finance callback, "
                    "and who owns residual phishing risk."
                ),
                how=(
                    "  1. Move from ticket language to program language.\n"
                    "  2. Keep owners visible.\n"
                    "  3. Mention evidence/metrics lightly."
                ),
                trap="only saying we told users to be careful.",
                remember="Oversight is how one ticket becomes fewer tickets.",
            ),
        ),
    ],
)
'''
