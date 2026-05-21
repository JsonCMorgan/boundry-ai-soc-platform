# Hiring Manager Lines

A running list of interview-ready statements Jason can use to demonstrate practical security knowledge.
Add a new line every session.

---

## Code Auditing & Testing

**Reading security regression tests:**
"I can read a security regression test and explain what payload it sends, what the safe output looks like, and what vulnerability it would catch if it failed."

**SQL Injection vs XSS:**
"I know the difference between XSS and SQL injection — one targets the browser, one targets the database — and I can identify which fix addresses which attack."

**Smoke tests vs regression tests:**
"I understand the difference between a smoke test and a security regression test — one checks basic functionality, the other guards against a specific vulnerability coming back."

---

## Vulnerabilities & Fixes

**SELECT * over-exposure:**
"I can audit a query for over-exposure — if a route only needs two columns, I'd flag a SELECT * as a medium severity finding and explain why least privilege applies at the database layer too."

**Severity ratings:**
"I understand that severity isn't just about what the vulnerability is — it's about how many steps an attacker needs to actually exploit it."

**DEBUG=True in production:**
"I know that DEBUG=True in production isn't just a minor leak — it exposes an interactive server console that gives an attacker full code execution."

---

## Authentication & Sessions

**bcrypt + salting:**
"I know bcrypt uses salting so identical passwords produce different hashes — that defeats rainbow table attacks even if the database is fully compromised."

**Route-level access control:**
"I know that hiding a link in the UI is not access control — every protected route must independently verify the session. I've implemented a login_required decorator that enforces this and written regression tests to prove it."

**Signed session cookies:**
"I understand why Flask's secret key matters — without it, an attacker can forge session cookies and impersonate any user without knowing their password."

**A01 vs A07:**
"I know the difference between A01 and A07 — one is about what you can access, the other is about how identity is verified. They're related but distinct findings in an audit."

---

## SIEM & SOC

**Splunk on real app logs:**
"I connected a Flask application I built to Splunk, wrote detection queries for brute force and injection attempts, and built an alert dashboard — I didn't just read about SIEM, I used it."

**SPL brute force detection:**
"I wrote an SPL (Search Processing Language) query in Splunk that counts failed login attempts per username and flags accounts exceeding a threshold — that's a real brute force detection rule running against live application logs."

**False positive tuning:**
"I know that detection rules need to be tuned — I identified false positives in my SQL injection query where normal search terms were matching the pattern, tightened the regex, and reduced noise from 3 results to 1 without missing the real attack."

**Security dashboard:**
"I built a Splunk dashboard with two live detection panels — one for brute force login attempts and one for SQL injection — both running against logs from a Flask application I instrumented myself."

**Registration route security:**
"I built and audited a registration route end to end — I identified user enumeration as a medium severity finding, fixed it with a generic error message, enforced server-side validation that can't be bypassed by skipping the browser, and wrote 6 regression tests to lock in the behavior."

**Client-side vs server-side validation:**
"I know client-side validation is for user experience and server-side validation is for security — an attacker can bypass the browser entirely and POST directly to the route, so the server must always be the enforcer."

---

---

## Cloud Deployment & DevOps

- "I deployed a Flask security application to Railway with PostgreSQL, configuring environment variables for secret key management and setting up automatic deployments from GitHub — the same CI/CD pattern used in production engineering teams."
- "I understand why SQLite is unsuitable for cloud deployment — the ephemeral filesystem means data is lost on every redeploy — and I migrated the app to PostgreSQL to solve this."

---

## Security Automation & SOAR

- "I understand SOAR — Security Orchestration, Automation and Response — and built an automated pipeline that detects brute force and SQL injection attacks, generates plain-English incident reports using AI, and stores them in a persistent database."
- "I automated the threat detection cycle with a scheduled job, reducing Mean Time To Detect from 'whenever someone checks' to under one hour — that's the core value proposition of any SOC monitoring service."

---

*Last updated: May 2026*
