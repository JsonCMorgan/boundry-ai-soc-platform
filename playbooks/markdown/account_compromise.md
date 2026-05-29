# Account Compromise — What It Is and What We Do About It

**Severity: HIGH** | Last Updated: May 2026

---

## What Is Account Compromise?

Account compromise means someone has stolen valid login credentials and is using them to access systems they shouldn't be in. The defining characteristic is that they look legitimate — they have real usernames and real passwords. There's no malware, no obvious intrusion. The attacker just... logs in.

This makes it significantly harder to detect than a traditional hack. The logs show a successful login. The account is doing normal things. The difference is the IP address is in another country, the login is at 3 AM, and the account is accessing files the employee hasn't touched in six months.

This is where continuous SIEM monitoring earns its place. Humans can't review every login. Automated rules that flag "same account, impossible geography, off-hours, followed by unusual file access" catch what manual review misses.

---

## How Attackers Get the Credentials

**Brute Force:** Try thousands of password combinations until one works. We detect this with the SIEM — it generates a wall of failed login events before the eventual success.

**Credential Stuffing:** Use a list of leaked usernames and passwords from previous breaches on other sites. If your staff reuse passwords across sites, when that other site gets breached, your system gets breached too. This is why "Password1!" is the password on millions of accounts — it was in breaches, it was stuffed, it worked somewhere.

**Password Spray:** Try one common password ("Summer2024!") across hundreds of accounts. Only one failure per account — designed to stay under lockout thresholds. Harder to detect, which is exactly why it's used.

**Phishing:** The most common. Someone tricks a staff member into entering their password into a fake login page.

---

## What We Do If It Happens

### Step 1 — Confirm and Scope
We verify the compromise is real (not a false positive) and determine how many accounts are affected. We look at where the attacker went — which files they opened, which systems they accessed, whether they tried to escalate their privileges to an admin account.

We also establish how long they've been in. Dwell time matters — the longer they had access, the more data they may have read or copied.

### Step 2 — Lock Out the Attacker Simultaneously
We reset passwords on all affected accounts at the same time — not one at a time. Doing them in sequence gives the attacker time to pivot to accounts you haven't secured yet.

We also invalidate all active sessions. A password reset alone isn't enough — the attacker may have a session cookie or token that stays valid despite the password change. Terminating sessions kicks them out completely.

### Step 3 — Enable Multi-Factor Authentication
If MFA wasn't in place before, it goes on now. An attacker with a stolen password and no MFA is inside. An attacker with a stolen password and MFA is locked out. This is the single most effective control for account security.

### Step 4 — Find Out How They Got In
We identify the attack method so we can prevent recurrence. If it was phishing, we work on email security and training. If it was credential stuffing, we enforce unique password requirements and check HaveIBeenPwned for affected email addresses.

### Step 5 — Notify Appropriately
Whether notification is required depends on what the attacker accessed while they were in:

- If they accessed files containing personal information → breach notification obligations apply
- If they accessed patient records → HIPAA breach assessment required
- If they processed payments → PCI DSS notification required
- Notify affected staff: tell them their credentials were compromised and ask them to change any passwords they've reused elsewhere (they probably have)

---

## What Protects Against This

**MFA is non-negotiable.** We advocate for it on every client account from day one. One extra step at login is the difference between a stolen password being a catastrophe and a stolen password being a non-event.

**Unique passwords matter.** A password manager removes the friction of having different passwords on every site. We recommend this to all clients.

**Monitoring is the backstop.** Even with MFA, determined attackers find ways. Our SIEM monitors for impossible travel, unusual access patterns, and off-hours logins so we catch compromises that get through other controls.

---

## Questions?

If a staff member thinks their password may have been compromised — or received a notification that their email appeared in a data breach — contact Jason immediately. Don't just change the password; we need to check whether the account was accessed while the old password was in use.

---

*Boundry.AI Incident Response Playbook — Business Edition*
*Technical version: playbooks/yaml/account_compromise.yaml*
