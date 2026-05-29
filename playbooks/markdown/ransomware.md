# Ransomware Attack — What It Is and What We Do About It

**Severity: CRITICAL** | Last Updated: May 2026

---

## What Is Ransomware?

Ransomware is malicious software that locks a business out of its own files and demands payment to get them back. Think of it like a criminal changing all the locks on your building and sliding a note under the door: "Pay us or you never get back in."

Modern ransomware attacks also steal the data *before* locking it — meaning even if you pay and get your files back, they can still threaten to publish your client records, financial data, or patient information publicly. This is called "double extortion."

For our clients — dispensaries, medical offices, law firms — a ransomware attack doesn't just mean downtime. It means regulatory fines, breach notifications to hundreds of clients, potential lawsuits, and in some cases, total business closure. The average small business ransom demand in 2025 is $120,000. Most businesses that experience one are out of business within a year.

---

## How It Usually Starts

Someone receives an email that looks legitimate — an invoice, a job application, a delivery notification. They open an attachment or click a link. In the background, software silently installs itself on their computer. The attacker waits, watches, and then at a chosen moment, deploys the attack across the network.

The time between the initial click and the encryption starting is usually measured in hours to days. Our SIEM monitors for the warning signs in that window — that's where we can stop it.

---

## What We Do If It Happens

### Step 1 — Find It Before It Spreads
Before we do anything else, we figure out exactly what's been hit. How many computers? Which ones? Did it spread across the network? We look at logs and monitor alerts to build a picture before we start pulling cables.

*Why this matters: Pulling the plug on the wrong machine can make things worse and destroy evidence we need.*

### Step 2 — Isolate the Affected Computers
We physically disconnect the affected machines from the network — not shut them down, disconnect them. Shutting down can destroy evidence and sometimes wipes out the only copy of the decryption key from computer memory.

We also block certain network traffic at the firewall level to stop any spread that's already in progress.

### Step 3 — Clean Up Completely
We wipe every infected computer and rebuild from a known clean backup. We do not try to clean the malware off an infected machine — we replace it entirely. Attempting to save an infected system is like trying to un-contaminate a petri dish.

Every password the attacker might have seen gets changed. Every account that was active during the attack gets a new password.

### Step 4 — Restore from Backups
We restore your data from the most recent clean backup. We verify the backups weren't themselves touched by the attack before we restore from them.

We bring your most critical systems back first — identity, email, key business applications — then work outward.

### Step 5 — Notify Who Needs to Know
This part has legal deadlines attached to it. Depending on your industry and what data was involved:

- **If you hold Canadian personal information (PIPEDA):** Report to the Office of the Privacy Commissioner and notify affected individuals within roughly 72 hours of confirming a breach.
- **If you're in healthcare (HIPAA):** Notify the Department of Health and Human Services and affected patients within 60 days.
- **If you process payment cards (PCI DSS):** Notify your card brands and bank immediately.
- **Law enforcement:** We report to the FBI's Internet Crime Complaint Center (ic3.gov) regardless. This creates an official record and may assist recovery.

---

## What We're Watching For (All the Time)

Our monitoring platform is specifically configured to catch ransomware behaviour in the early stages:

- Phishing emails arriving in the inbox
- Someone opening a malicious macro or file
- Windows Defender or antivirus being turned off
- Backup files or shadow copies being deleted
- Rapid file renaming (which is what encryption looks like to a monitoring system)

Every one of those events generates an alert in our SIEM and can trigger a finding for us to review.

---

## Key Dates and Deadlines (Quick Reference)

| Regulation | Who It Applies To | Notify | Deadline |
|---|---|---|---|
| PIPEDA (Canada) | Any Canadian personal data | OPC + affected individuals | ~72 hours |
| HIPAA | Healthcare/patient data | HHS + patients | 60 days |
| PCI DSS | Payment card data | Card brands + bank | Immediately |
| CISA/CIRCIA | Critical infrastructure | CISA federal agency | 72 hours |

---

## Questions?

If you're ever unsure whether something is a ransomware risk or you've received a suspicious email, reach out to Jason directly before clicking anything. The earlier we know, the more options we have.

---

*Boundry.AI Incident Response Playbook — Business Edition*
*Technical version: playbooks/yaml/ransomware.yaml*
