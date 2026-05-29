# Insider Threat — What It Is and What We Do About It

**Severity: HIGH** | Last Updated: May 2026

---

## What Is an Insider Threat?

An insider threat is a security incident caused by someone who already has legitimate access to your business systems. That includes:

- **Current employees** who misuse their access — whether deliberately (stealing data, sabotage) or accidentally (clicking a phishing link, sending a file to the wrong person)
- **Contractors or vendors** with system access who go beyond their authorised scope
- **Former employees** whose accounts were not properly deactivated when they left

The reason insiders are particularly dangerous is that they don't need to hack their way in. They're already authorised. There's no brute force, no phishing email, no malware trigger. They open the file they're allowed to open and download it to a USB drive. Without monitoring, that looks completely normal.

---

## The Two Types

**Malicious Insider:** Intentionally stealing data, sabotaging systems, or committing fraud. Classic examples: an employee about to leave to a competitor downloading the client list; a disgruntled IT admin deleting backups; an accounts payable employee redirecting payments.

**Negligent Insider:** Not malicious, just careless. Emailing a spreadsheet with client records to their personal email "to work from home." Leaving a laptop in a taxi. Clicking a phishing link and not reporting it. Sharing a password with a colleague to cover a vacation.

**Statistically, negligent insiders cause more breaches than malicious ones.** Security awareness training and clear policies address this category. The malicious insider is the one that requires a coordinated, careful response.

---

## The Most Important Thing to Know

**Do not tip off the subject.** This is not a normal incident where you immediately lock down the system and tell everyone what happened. If the subject realises they're under investigation, they will:

- Delete evidence
- Accelerate the data theft
- Involve a lawyer before you're ready to act
- Claim wrongful termination or discrimination pre-emptively

Every action from the moment you suspect an insider threat needs to be coordinated with HR and legal counsel before you do it. The investigation runs in the background, silently, until you're ready to act.

---

## What We Do If It Happens

### Step 1 — Gather Evidence Quietly
We review the logs and monitoring data we already have — we don't expand monitoring in ways that could be noticed. We build a timeline of the suspicious activity: what was accessed, when, for how long, and what happened to it.

We document everything with timestamps. This record may be needed in legal proceedings.

### Step 2 — Get HR and Legal Involved Immediately
Before any action is taken, HR and legal counsel need to be part of the plan. This protects the business from:
- Wrongful termination claims
- Privacy violations from improper monitoring
- Evidence being inadmissible because the chain of custody was broken

We provide the technical evidence. HR and legal determine the business action.

### Step 3 — Coordinate the Response
Access is revoked in a coordinated way — timed to coincide with the HR conversation (termination meeting, disciplinary action, etc.). We revoke access in sequence: remote access first, then email, then file systems, then physical badges — all within minutes of each other to minimise the window where the subject might still have partial access.

We take a forensic copy of the relevant systems before anything is wiped or reassigned.

### Step 4 — Change Every Shared Credential
Any shared passwords, system accounts, or access credentials the insider had access to get rotated. Service accounts, admin accounts, VPN credentials, physical key codes.

### Step 5 — Audit and Tighten
We review whether the scope of the insider's access was appropriate to their role. In many insider threat cases, the damage is as large as it is because the person had access they didn't need.

Going forward: least privilege access (people only have access to what their job requires), regular access audits, and a defined offboarding checklist.

### Step 6 — Notify Appropriately
If personal data, health records, or financial data was taken or misused:

- The same breach notification obligations apply as with any other breach
- Law enforcement involvement is often appropriate for malicious insiders — especially if theft of trade secrets or fraud is involved
- Affected clients should be notified if their data was involved — legal can advise on timing and language

---

## Signs We Watch For

Our monitoring looks for:
- Access to data that doesn't match someone's job function
- Large downloads at unusual hours
- Access to sensitive files in the lead-up to someone's last day
- Account activity after an employee has officially left
- Systems being accessed from outside the office when someone is supposed to be in

---

## A Practical Note for Business Operations

The most common insider incidents we see in small businesses are negligent, not malicious — and they're preventable:

1. **Clear offboarding checklist:** When someone leaves, their accounts are disabled the same day. Not "when IT gets to it." Same day.
2. **Data handling policy:** Staff know what they can and can't do with company data. No emailing client lists to personal accounts. No taking files on a USB drive without approval.
3. **Access reviews:** Every 6 months, review who has access to what. You'll find former employees still active, accounts with more permissions than the role needs, and contractors who stopped working with you 8 months ago.

---

## Questions?

If you notice a staff member behaving unusually around data — downloads that seem large, access to files outside their area, someone who seems to be "taking things with them" before leaving — contact Jason privately and directly. Do not confront the employee or investigate on your own.

---

*Boundry.AI Incident Response Playbook — Business Edition*
*Technical version: playbooks/yaml/insider_threat.yaml*
