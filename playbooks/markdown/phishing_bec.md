# Phishing & Business Email Compromise — What It Is and What We Do About It

**Severity: HIGH** | Last Updated: May 2026

---

## What Is Phishing?

Phishing is a fake email designed to trick someone into giving up their password, opening a malicious file, or clicking a link that installs software on their computer. The email might look like it's from a supplier, a courier company, your bank, or even a colleague.

**Business Email Compromise (BEC)** is a specific, more sophisticated version where the attacker actually gets inside a legitimate company email account — yours or a supplier's — and uses it to send convincing requests for money transfers, credential changes, or sensitive information. Because the email is coming from a real address the victim already trusts, most spam filters let it straight through.

This is the #1 attack vector for small businesses. 88% of data breaches begin with a phishing email.

---

## How It Usually Looks

**Scenario A — Credential Harvest:**
An employee receives an email that looks like a Microsoft 365 login page saying their account needs to be re-verified. They enter their username and password. The attacker now has their credentials.

**Scenario B — Business Email Compromise:**
Your supplier's email account has been compromised. The attacker, now reading all their emails, waits until the right moment and sends you an email from your supplier's real address saying "We've changed our banking details — please send this month's payment here instead." The email looks completely legitimate because it is coming from a real account.

**Scenario C — Internal Spearphishing:**
Once inside one account, the attacker sends phishing emails to the rest of the company from a trusted internal address, with a much higher success rate.

---

## What We Do If It Happens

### Step 1 — Find Out What Happened
We look at the email itself (without clicking anything) — the headers tell us where it really came from. We check the SIEM to see if anyone clicked, entered credentials, or opened attachments.

*If credentials were entered, we treat that account as compromised immediately.*

### Step 2 — Lock Down the Compromised Account
We reset the account password and kick out any active sessions right away. An active attacker session can persist even after a password change — invalidating sessions shuts them out completely.

We then check whether the attacker set up email forwarding rules (very common — they forward a copy of everything to themselves quietly).

If there's any chance of a fraudulent payment: **call the bank immediately.** This is the step where minutes matter.

### Step 3 — Stop the Spread
We block the sending domain and IP at the email gateway so no other staff receive the same phishing email. We send an internal alert to staff about the campaign — through a different channel, not email, in case other accounts are also compromised.

### Step 4 — Clean Up Completely
We check the compromised email account for any changes the attacker made: forwarding rules, new registered devices, linked apps, and OAuth authorisations. Everything the attacker touched gets reviewed and removed.

Any systems the compromised account had access to get their credentials changed.

### Step 5 — Notify Who Needs to Know
The notification question here comes down to: did the attacker *read* anything sensitive while they were in the account?

- If they accessed emails containing client personal information: breach notification applies
- If financial fraud occurred: notify your bank's fraud team and file a police report
- If healthcare data was in the inbox: HIPAA breach assessment required
- FBI IC3 (ic3.gov): always worth reporting — BEC is their #1 category by dollar loss, and they have a rapid response team for recent fraud

---

## What Protects Against This

Beyond our monitoring, these practices matter:

- **Multi-factor authentication (MFA):** Even if an attacker has the password, MFA stops them from logging in. This is the single most effective control against phishing.
- **"Call before you pay" policy:** Any change to payment details or any payment request over a certain amount requires a verbal phone confirmation — not email.
- **Phishing training:** Staff who can recognise a suspicious email are the first line of defence.

---

## Questions?

Received a suspicious email? Forward it to Jason — do not click any links. We can analyse the headers and tell you whether it's legitimate without putting anything at risk.

---

*Boundry.AI Incident Response Playbook — Business Edition*
*Technical version: playbooks/yaml/phishing_bec.yaml*
