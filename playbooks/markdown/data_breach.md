# Data Breach & Data Theft — What It Is and What We Do About It

**Severity: CRITICAL** | Last Updated: May 2026

---

## What Is a Data Breach?

A data breach is any incident where personal, financial, or confidential information is accessed or taken by someone who isn't supposed to have it. It doesn't require ransomware or a hacker in a hoodie. A breach can be:

- **External attack:** Someone exploits a vulnerability in your website or software to pull data from your database
- **Misconfigured storage:** A cloud file share or database is accidentally set to public — anyone with the link can download it
- **Stolen device:** A laptop with unencrypted client data is stolen from a car
- **Credential theft:** A staff member's password is stolen and used to access client files
- **Insider:** An employee downloads client lists before leaving to go to a competitor

What matters is not how it happened — it's *what data was accessed* and *who it belongs to.*

---

## Why This Matters More Than Most People Realise

The moment a breach happens, a clock starts. Regulators do not care how busy you were, how overwhelmed your team is, or whether you're still figuring out what happened. The deadline for notification runs from the moment you first became aware of the incident — not from when you've finished investigating it.

Missing a notification deadline is a separate regulatory violation on top of the breach itself. For small businesses, the fines for missing a PIPEDA notification deadline can be as significant as the fine for the breach.

---

## What We Do If It Happens

### Step 1 — Figure Out Exactly What Was Taken
Before we do anything else, we need to know: what data was accessible from the point of entry? This determines your legal obligation. A break-in through a back door that only leads to the supply closet is very different from one that leads straight to the filing cabinet with every client record you have.

We review access logs, database queries, outbound transfers, and file activity to build an accurate picture. Guessing at scope is not good enough — the regulator will ask specifically.

### Step 2 — Stop the Leak
Once we know the entry point, we close it. That might mean:
- Disabling a specific feature on your website
- Revoking a set of stolen credentials
- Fixing a misconfigured storage setting
- Taking a compromised system offline

We also block the attacker from reaching out to anything they were sending data to.

### Step 3 — Remove Every Foothold
A breach often involves more than one path. We audit everything the attacker had access to, change every password they might have seen, and verify there are no back doors left behind.

### Step 4 — Restore
We restore your data from clean backups where needed. We also build in better controls going forward — tighter permissions, better monitoring, stronger access rules.

### Step 5 — Notify the Right People
This is where it gets serious from a business perspective. Depending on what was breached:

**PIPEDA (Canada — personal information of any Canadian):**
Report to the Office of the Privacy Commissioner and notify affected individuals as soon as feasible — the OPC's interpretation is typically 72 hours for high-risk situations.

**HIPAA (US — patient health information):**
Notify the Department of Health and Human Services and affected patients within 60 days. If 500+ people in a single state are affected, media notification is also required.

**PCI DSS (payment card data):**
Notify Visa, Mastercard, and your bank immediately — they launch their own investigation.

**GLBA (US — financial data):**
Notify your primary federal financial regulator within 30 days.

We prepare the written notifications and help you get them right. Getting the notification wrong is almost as bad as sending it late.

---

## What We Watch For

Our monitoring is set up to catch data exfiltration in the act:

- Large outbound data transfers to unfamiliar destinations
- Unusual database query volumes — someone running a "SELECT * FROM customers" at 2 AM
- File access from accounts that have no business reason to access that file
- Compression tools being used on file servers (staging for upload)

---

## One Thing That Catches Business Owners Off Guard

You may be obligated to notify even if the data was only *accessed*, not actually downloaded or misused. Under HIPAA, accessing a system containing patient health information — even without downloading anything — is a reportable breach unless you can demonstrate the data was not acquired. Under PIPEDA, "access" to personal information counts as a breach if there is real risk of harm.

When in doubt: notify. The cost of an unnecessary notification is embarrassment. The cost of a missed required notification is fines, legal liability, and loss of client trust.

---

## Questions?

If you become aware of anything that sounds like it might be a breach — a missing laptop, an unusual login, a client saying they received a suspicious email from your address — tell Jason immediately. Do not investigate on your own, and do not use potentially compromised systems to do it.

---

*Boundry.AI Incident Response Playbook — Business Edition*
*Technical version: playbooks/yaml/data_breach.yaml*
