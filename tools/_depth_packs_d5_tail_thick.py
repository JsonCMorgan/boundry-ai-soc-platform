"""Thickened D5 lessons 08-11. Executed by apply after body/put exist."""

put(
    "sp_d5_08_pen_vs_vuln",
    18,
    [
        (
            "Pen test vs vuln scan",
            body(
                orient=(
                    "A vulnerability scan finds known weaknesses broadly and often. A penetration "
                    "test simulates attacker techniques to prove exploitable paths, usually with "
                    "defined scope and rules of engagement (ROE)."
                ),
                work=(
                    "weekly Nessus finds missing patches and open ports. An annual pen test proves "
                    "whether an open path can reach the domain controller. Different questions, "
                    "different outputs, same need for remediation owners."
                ),
                formal="penetration testing versus vulnerability scanning",
                beats=(
                    "Contrast:\n"
                    "  Vuln scan → breadth, known issues, frequent, lower impact if configured safely\n"
                    "  Pen test → depth, exploitation/proof, scoped, higher skill/cost\n"
                    "  Red team → broader adversary simulation (related idea)\n"
                    "  Bug bounty → external researcher program (related idea)"
                ),
                tech=(
                    "  - Scans need authorization and safety (Domain 4 overlap): CHG, scope, stop conditions\n"
                    "  - Pen tests need ROE, contacts, data handling, get-out-of-jail letter, stop conditions\n"
                    "  - Scan cadence can be weekly/monthly; pen tests are usually deeper and less frequent\n"
                    "  - Neither replaces patching or path removal\n"
                    "  - Both produce findings that enter the same remediation/risk process\n"
                    "  - A clean scan does not prove no exploitable business path exists"
                ),
                worked=(
                    "Open RDP may show on a scan as exposure/misconfig and also be a pen-test "
                    "finding if exploited to the DC.\n"
                    "  - Question wants breadth discovery → vuln scan\n"
                    "  - Question wants exploit proof / path to crown jewel → pen test\n"
                    "  - Skipping fixes because 'pen test next year' fails both programs"
                ),
                how=(
                    "  1. Ask if the question wants breadth discovery or exploit proof.\n"
                    "  2. Match scan vs pen test.\n"
                    "  3. Keep authorization in view."
                ),
                trap=(
                    "calling a vuln scan a pen test because it has a red logo, or skipping fixes "
                    "because a pen test is scheduled next year. Near-miss: equating any scanner "
                    "output with 'we were pen tested.'"
                ),
                remember="Scan finds. Pen test proves. Both need remediation owners.",
            ),
        ),
        (
            "Rules of engagement",
            body(
                work="tester starts attacking prod payroll at noon with no window or contact.",
                formal="authorization and ROE for offensive assessments",
                beats=(
                    "ROE beats: scope, timing, contacts, data handling, stop conditions, "
                    "get-out-of-jail letter."
                ),
                tech=(
                    "  - Unauthorized testing is illegal and an incident\n"
                    "  - Findings still need treatment like other risks (owner, due date, verify)\n"
                    "  - Production windows and emergency contacts prevent payroll outages"
                ),
                worked=(
                    "No ROE = stop. Good programs treat findings through the risk register, not "
                    "a slide deck that dies in email."
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
    17,
    [
        (
            "Awareness that changes behavior",
            body(
                orient=(
                    "Security awareness teaches people how to recognize and report risks. It is "
                    "a control layer, not a substitute for technical guardrails like ASR, MFA, and DLP."
                ),
                work=(
                    "phishing simulations, short role tips for finance callbacks, and reporting "
                    "paths that do not shame accidental clicks. Metrics track report rate and "
                    "time-to-report, not only course completion checkmarks."
                ),
                formal="security awareness program basics",
                beats=(
                    "Awareness beats:\n"
                    "  1. Relevant content (phishing, BEC, USB, travel)\n"
                    "  2. Frequency that sticks\n"
                    "  3. Easy reporting\n"
                    "  4. Metrics (report rate, click trends) without shame culture\n"
                    "  5. Pair with technical ASR / MFA / DLP"
                ),
                tech=(
                    "  - Measure report quality and time-to-report, not only completion checkmarks\n"
                    "  - Pair every awareness theme with a technical control (ASR, MFA, DLP)\n"
                    "  - Keep reporting frictionless: button/mailbox and a thank-you response\n"
                    "  - Shame culture suppresses the human sensor network\n"
                    "  - Poster-only after confirmed BEC is incomplete\n"
                    "  - Stale training (14+ months) is a process gap"
                ),
                worked=(
                    "After Invoice.xlsm: AUP helps set expectations, but ASR still required. "
                    "Awareness last updated 14 months ago is a process gap. "
                    "Annual boring slideshow as the only control for active phishing fails."
                ),
                how=(
                    "  1. Prefer awareness + technical pairing.\n"
                    "  2. Reject shame-only answers.\n"
                    "  3. Look for reporting path clarity."
                ),
                trap=(
                    "annual boring slideshow as the only control for active phishing. Near-miss: "
                    "mocking the clicker in all-hands so nobody reports next time."
                ),
                remember="Awareness steers humans. Technical controls still close paths.",
            ),
        ),
        (
            "Reporting culture",
            body(
                work="user almost clicks, then reports. Analyst thanks them and checks the campaign.",
                formal="positive reporting culture as part of awareness effectiveness",
                beats=(
                    "Good culture: fast thank-you, no public shaming, rapid block of related IOCs."
                ),
                tech=(
                    "  - Report button / dedicated mailbox\n"
                    "  - Feed reports into detections and block lists\n"
                    "  - Track time from report to block"
                ),
                worked=(
                    "Punishing reporters kills the detection source you need. Thank, hunt, harden."
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
    17,
    [
        (
            "Role-based awareness",
            body(
                orient=(
                    "Different jobs need different awareness. Finance is not HR is not admins. "
                    "Privileged users are higher-value targets."
                ),
                work=(
                    "finance gets BEC callback drills and payment-change verification. Admins get "
                    "phishing-resistant MFA and privileged account hygiene. Helpdesk gets identity "
                    "verification before resets. Developers get secrets-in-git training."
                ),
                formal="role-based security awareness and privileged-user training",
                beats=(
                    "Role map:\n"
                    "  Finance → BEC / payment change verification\n"
                    "  Executives → high-value targeting, travel process\n"
                    "  Admins → privileged phishing, tool hygiene, no daily email on DA\n"
                    "  Helpdesk → verify before reset; MFA fatigue resistance\n"
                    "  All staff → phishing basics + reporting"
                ),
                tech=(
                    "  - Track metrics by role so exec/finance risk is not hidden in org averages\n"
                    "  - Privileged users are higher-value targets; pair training with IAM controls\n"
                    "  - Number matching / phishing-resistant MFA reduces fatigue abuse\n"
                    "  - Helpdesk verification procedures are awareness + procedure\n"
                    "  - Generic annual training alone fails finance BEC scenarios\n"
                    "  - Finance drills: out-of-band callback before payment-detail changes\n"
                    "  - Admins: no daily email on Domain Admin / Global Admin accounts"
                ),
                worked=(
                    "Generic annual training alone fails finance BEC. Add callback drills + technical "
                    "forward controls. "
                    "Helpdesk resetting a VIP without verification is an awareness and process miss. "
                    "Measure finance report rate separately so org-wide averages do not hide the risk."
                ),
                how=(
                    "  1. Match training to role risk.\n"
                    "  2. Pair with technical controls.\n"
                    "  3. Keep privileged training stricter."
                ),
                trap=(
                    "one identical slideshow for every role forever. Near-miss: assuming admins "
                    "already know and skipping their training."
                ),
                remember="Train the job people actually do.",
            ),
        ),
        (
            "Privileged targets",
            body(
                work=(
                    "helpdesk and domain admins receive convincing MFA fatigue or helpdesk "
                    "impersonation lures."
                ),
                formal="elevated awareness for privileged and helpdesk roles",
                beats=(
                    "Extra topics: MFA fatigue, vishing, password reset verification, out-of-band checks."
                ),
                tech=(
                    "  - Number matching / phishing-resistant MFA reduces fatigue abuse\n"
                    "  - Helpdesk verification procedures are awareness + procedure\n"
                    "  - No daily email on privileged admin accounts"
                ),
                worked=(
                    "Helpdesk resetting a VIP without verification is an awareness and process miss. "
                    "Combine training with IAM tech and callbacks."
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
    18,
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
                    "record residual risk (risk), brief finance (awareness), review vendor mail "
                    "filter access if implicated, and evidence the change for audit."
                ),
                formal="tying program oversight actions back to operational incidents",
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
                    "  - After IR, name the program object that changes: standard, exception, "
                    "risk row, training, vendor access\n"
                    "  - Metrics that matter: repeat incident rate, aged exceptions, privileged "
                    "training completion by role\n"
                    "  - Unowned 'next steps' in tickets become next quarter's identical alert\n"
                    "  - Portfolio What/Why/Disposition/Next is an oversight-friendly artifact\n"
                    "  - Vendors implicated in the path get access reviews"
                ),
                worked=(
                    "Repeat Invoice.xlsm without ASR update + role training means oversight failed "
                    "to close the loop even if each ticket was resolved. "
                    "Interview answer: disable legacy auth, forward controls, finance callback drill, "
                    "who owns residual phishing risk, and where evidence lives."
                ),
                how=(
                    "  1. After the firefight, ask what program object changes.\n"
                    "  2. Name owner and date.\n"
                    "  3. Prefer loop-closing answers over one-off heroics."
                ),
                trap=(
                    "closing incidents forever with no policy/risk/awareness follow-through. "
                    "Near-miss: only saying we told users to be careful."
                ),
                remember="Owner, treatment, vendor, awareness. Close the loop.",
            ),
        ),
        (
            "Program talk-track",
            body(
                work="interview: how do you prevent the same BEC next quarter?",
                formal="program-level prevention language after IR",
                beats=(
                    "Talk-track: technical eradicate + standard update + finance drill + residual "
                    "risk review + evidence."
                ),
                tech=(
                    "  - Metrics: repeat incident rate, exception aging, training completion by role\n"
                    "  - Escalation path into leadership when appetite is exceeded\n"
                    "  - Oversight talk-track beats 'we told users to be careful'"
                ),
                worked=(
                    "Strong answer names disable legacy auth, forward controls, finance callback, "
                    "and who owns residual phishing risk. Weak answer stops at awareness posters."
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
