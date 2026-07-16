"""
Boundry.AI — Security acronym library.

A single curated source of common cybersecurity / CISSP acronyms, used by:
  - the Glossary index page (study reference)
  - the acronym quiz (multiple-choice drill)
  - the site-wide hover tooltips

Each entry: abbr, full (expansion), definition (short plain-English), cat (category).
Kept deliberately security/CISSP-focused. Tune freely.
"""

# category -> display label (controls glossary grouping + colour on the frontend)
ACRONYM_CATEGORIES = {
    "risk":       "Risk & Governance",
    "access":     "Identity & Access",
    "crypto":     "Cryptography",
    "network":    "Network & Infrastructure",
    "secops":     "Security Operations",
    "threat":     "Threats & Attacks",
    "compliance": "Compliance & Frameworks",
    "general":    "General IT",
}

# (abbr, full, definition, category)
_ACRONYMS = [
    # ── Risk & Governance ──────────────────────────────────────────────────
    ("CIA",  "Confidentiality, Integrity, Availability", "The three core goals of information security.", "risk"),
    ("AAA",  "Authentication, Authorization, Accounting", "The three pillars of access control.", "risk"),
    ("GRC",  "Governance, Risk, and Compliance", "The discipline of aligning security with business rules and law.", "risk"),
    ("BIA",  "Business Impact Analysis", "Identifies critical processes and the cost of losing them.", "risk"),
    ("BCP",  "Business Continuity Plan", "How the business keeps running during a disruption.", "risk"),
    ("DRP",  "Disaster Recovery Plan", "How IT systems are restored after a disaster.", "risk"),
    ("RTO",  "Recovery Time Objective", "Max acceptable time to restore a system after an outage.", "risk"),
    ("RPO",  "Recovery Point Objective", "Max acceptable amount of data loss, measured in time.", "risk"),
    ("MTD",  "Maximum Tolerable Downtime", "The longest an outage can last before the business fails.", "risk"),
    ("MTTR", "Mean Time To Repair", "Average time to fix a failed component.", "risk"),
    ("MTBF", "Mean Time Between Failures", "Average time a component runs before failing.", "risk"),
    ("SLE",  "Single Loss Expectancy", "Expected dollar loss from one incident (Asset Value x Exposure Factor).", "risk"),
    ("ALE",  "Annualized Loss Expectancy", "Expected yearly loss from a risk (SLE x ARO).", "risk"),
    ("ARO",  "Annualized Rate of Occurrence", "How many times per year a threat is expected to occur.", "risk"),
    ("EF",   "Exposure Factor", "Percentage of an asset's value lost in a single incident.", "risk"),
    ("KRI",  "Key Risk Indicator", "A metric that signals rising risk exposure.", "risk"),
    ("KPI",  "Key Performance Indicator", "A metric that measures performance against a goal.", "risk"),
    ("SLA",  "Service Level Agreement", "A contract defining expected service levels and penalties.", "risk"),

    # ── Identity & Access ──────────────────────────────────────────────────
    ("IAM",  "Identity and Access Management", "Managing who can access what, and proving who they are.", "access"),
    ("MFA",  "Multi-Factor Authentication", "Requiring two or more proofs of identity to log in.", "access"),
    ("2FA",  "Two-Factor Authentication", "A form of MFA using exactly two factors.", "access"),
    ("SSO",  "Single Sign-On", "One login that grants access to many systems.", "access"),
    ("RBAC", "Role-Based Access Control", "Access granted based on a user's job role.", "access"),
    ("ABAC", "Attribute-Based Access Control", "Access granted based on attributes (time, location, etc.).", "access"),
    ("MAC",  "Mandatory Access Control", "Access enforced by system-wide policy, not the owner.", "access"),
    ("DAC",  "Discretionary Access Control", "Access decided by the resource owner.", "access"),
    ("PAM",  "Privileged Access Management", "Securing and monitoring admin / high-power accounts.", "access"),
    ("PoLP", "Principle of Least Privilege", "Give users only the access they truly need.", "access"),
    ("LDAP", "Lightweight Directory Access Protocol", "Protocol for querying directory services like AD.", "access"),
    ("SAML", "Security Assertion Markup Language", "XML standard for exchanging authentication between systems.", "access"),
    ("OIDC", "OpenID Connect", "Identity layer built on top of OAuth 2.0.", "access"),
    ("JIT",  "Just-In-Time (access)", "Granting privileges only for the moment they are needed.", "access"),

    # ── Cryptography ───────────────────────────────────────────────────────
    ("PKI",  "Public Key Infrastructure", "The system of keys, certs, and CAs enabling trust.", "crypto"),
    ("CA",   "Certificate Authority", "A trusted entity that issues digital certificates.", "crypto"),
    ("CRL",  "Certificate Revocation List", "A list of certificates that are no longer valid.", "crypto"),
    ("OCSP", "Online Certificate Status Protocol", "Real-time check of a certificate's revocation status.", "crypto"),
    ("AES",  "Advanced Encryption Standard", "The modern standard symmetric encryption algorithm.", "crypto"),
    ("RSA",  "Rivest-Shamir-Adleman", "A widely used asymmetric (public-key) algorithm.", "crypto"),
    ("ECC",  "Elliptic Curve Cryptography", "Asymmetric crypto with strong security at small key sizes.", "crypto"),
    ("SHA",  "Secure Hash Algorithm", "A family of cryptographic hashing functions.", "crypto"),
    ("HMAC", "Hash-Based Message Authentication Code", "Verifies both integrity and authenticity of a message.", "crypto"),
    ("TLS",  "Transport Layer Security", "Encrypts data in transit; the successor to SSL.", "crypto"),
    ("SSL",  "Secure Sockets Layer", "Legacy transit encryption, now replaced by TLS.", "crypto"),
    ("HSM",  "Hardware Security Module", "A tamper-resistant device that stores and manages keys.", "crypto"),
    ("PGP",  "Pretty Good Privacy", "Encryption program often used to secure email.", "crypto"),

    # ── Network & Infrastructure ───────────────────────────────────────────
    ("VPN",  "Virtual Private Network", "An encrypted tunnel over an untrusted network.", "network"),
    ("VLAN", "Virtual Local Area Network", "A logically segmented network on shared hardware.", "network"),
    ("DMZ",  "Demilitarized Zone", "A buffer network exposing public services safely.", "network"),
    ("NAT",  "Network Address Translation", "Maps private IPs to a public one at the gateway.", "network"),
    ("DNS",  "Domain Name System", "Translates domain names into IP addresses.", "network"),
    ("DHCP", "Dynamic Host Configuration Protocol", "Automatically assigns IP addresses to devices.", "network"),
    ("SSH",  "Secure Shell", "Encrypted protocol for remote command-line access.", "network"),
    ("RDP",  "Remote Desktop Protocol", "Microsoft protocol for remote graphical access.", "network"),
    ("SMB",  "Server Message Block", "Windows file/printer sharing protocol (port 445).", "network"),
    ("WAF",  "Web Application Firewall", "Filters malicious traffic to a web application.", "network"),
    ("NAC",  "Network Access Control", "Enforces policy on devices before they join the network.", "network"),
    ("IDS",  "Intrusion Detection System", "Detects and alerts on suspicious network activity.", "network"),
    ("IPS",  "Intrusion Prevention System", "Detects AND blocks suspicious network activity.", "network"),
    ("UTM",  "Unified Threat Management", "An all-in-one security appliance (firewall, IPS, AV, etc.).", "network"),

    # ── Security Operations ────────────────────────────────────────────────
    ("SOC",  "Security Operations Center", "The team/facility that monitors and defends an org.", "secops"),
    ("SIEM", "Security Information and Event Management", "Collects and correlates logs to detect threats.", "secops"),
    ("SOAR", "Security Orchestration, Automation and Response", "Automates security workflows and incident response.", "secops"),
    ("EDR",  "Endpoint Detection and Response", "Monitors endpoints for threats and enables response.", "secops"),
    ("XDR",  "Extended Detection and Response", "Correlates detection across endpoints, network, and cloud.", "secops"),
    ("MDR",  "Managed Detection and Response", "Outsourced 24/7 threat detection and response service.", "secops"),
    ("DLP",  "Data Loss Prevention", "Technology that stops sensitive data from leaving the org.", "secops"),
    ("MDM",  "Mobile Device Management", "Centrally manages and secures mobile devices.", "secops"),
    ("FIM",  "File Integrity Monitoring", "Alerts when critical files are changed unexpectedly.", "secops"),
    ("UEBA", "User and Entity Behavior Analytics", "Detects threats by spotting abnormal behavior.", "secops"),
    ("IR",   "Incident Response", "The structured process of handling a security incident.", "secops"),
    ("CTI",  "Cyber Threat Intelligence", "Analyzed information about current and emerging threats.", "secops"),

    # ── Threats & Attacks ──────────────────────────────────────────────────
    ("APT",  "Advanced Persistent Threat", "A stealthy, well-resourced, long-term attacker.", "threat"),
    ("IOC",  "Indicator of Compromise", "Forensic evidence that a breach has occurred.", "threat"),
    ("TTP",  "Tactics, Techniques, and Procedures", "How an attacker operates; the core of MITRE ATT&CK.", "threat"),
    ("CVE",  "Common Vulnerabilities and Exposures", "A public catalog ID for a known vulnerability.", "threat"),
    ("CVSS", "Common Vulnerability Scoring System", "A 0-10 score rating a vulnerability's severity.", "threat"),
    ("C2",   "Command and Control", "The channel an attacker uses to control compromised hosts.", "threat"),
    ("DDoS", "Distributed Denial of Service", "Flooding a target from many sources to knock it offline.", "threat"),
    ("DoS",  "Denial of Service", "Overwhelming a system so it can't serve legitimate users.", "threat"),
    ("RCE",  "Remote Code Execution", "A flaw letting an attacker run code on a remote system.", "threat"),
    ("XSS",  "Cross-Site Scripting", "Injecting malicious scripts into a web page.", "threat"),
    ("CSRF", "Cross-Site Request Forgery", "Tricking a user's browser into an unwanted action.", "threat"),
    ("SQLi", "SQL Injection", "Injecting malicious SQL to manipulate a database.", "threat"),
    ("SSRF", "Server-Side Request Forgery", "Tricking a server into making attacker-chosen requests.", "threat"),
    ("MITM", "Man-in-the-Middle", "Intercepting communication between two parties.", "threat"),
    ("RAT",  "Remote Access Trojan", "Malware giving an attacker remote control of a host.", "threat"),
    ("BEC",  "Business Email Compromise", "Fraud via impersonating a trusted business contact.", "threat"),

    # ── Compliance & Frameworks ────────────────────────────────────────────
    ("NIST", "National Institute of Standards and Technology", "US agency behind key security frameworks.", "compliance"),
    ("CSF",  "Cybersecurity Framework", "NIST's framework: Identify, Protect, Detect, Respond, Recover.", "compliance"),
    ("GDPR", "General Data Protection Regulation", "EU privacy law with strict breach-notification rules.", "compliance"),
    ("HIPAA","Health Insurance Portability and Accountability Act", "US law protecting health information (PHI).", "compliance"),
    ("PCI DSS","Payment Card Industry Data Security Standard", "Rules for any business handling payment cards.", "compliance"),
    ("PIPEDA","Personal Information Protection and Electronic Documents Act", "Canada's federal private-sector privacy law.", "compliance"),
    ("SOX",  "Sarbanes-Oxley Act", "US law governing financial reporting and controls.", "compliance"),
    ("GLBA", "Gramm-Leach-Bliley Act", "US law protecting consumers' financial information.", "compliance"),
    ("ISO",  "International Organization for Standardization", "Body behind ISO 27001, the ISMS standard.", "compliance"),
    ("CIS",  "Center for Internet Security", "Publishes the CIS Controls and hardening benchmarks.", "compliance"),
    ("PII",  "Personally Identifiable Information", "Data that can identify a specific individual.", "compliance"),
    ("PHI",  "Protected Health Information", "Health data protected under HIPAA.", "compliance"),

    # ── General IT ─────────────────────────────────────────────────────────
    ("API",  "Application Programming Interface", "A defined way for software to talk to other software.", "general"),
    ("VM",   "Virtual Machine", "A software-based emulation of a physical computer.", "general"),
    ("OT",   "Operational Technology", "Hardware/software that controls physical processes.", "general"),
    ("ICS",  "Industrial Control System", "Systems that run industrial and critical infrastructure.", "general"),
    ("IoT",  "Internet of Things", "Everyday physical devices connected to the internet.", "general"),
    ("BYOD", "Bring Your Own Device", "Employees using personal devices for work.", "general"),
    ("SaaS", "Software as a Service", "Software delivered over the internet on subscription.", "general"),
]

# Optional cache of LLM-generated letter-matching distractors:
#   { "SIEM": ["Security Incident and Event Monitoring", ...], ... }
# Produced by generate_acronym_distractors.py. If absent, the quiz falls back to
# assembling distractors at runtime.
import os as _os, json as _json
_DISTRACTORS = {}
_dpath = _os.path.join(_os.path.dirname(__file__), "acronym_distractors.json")
try:
    if _os.path.exists(_dpath):
        _DISTRACTORS = _json.load(open(_dpath, encoding="utf-8"))
except Exception:
    _DISTRACTORS = {}

# Public list of dicts for templates/JSON.
ACRONYMS = [
    {"abbr": a, "full": f, "def": d, "cat": c,
     "distractors": _DISTRACTORS.get(a, [])}
    for (a, f, d, c) in _ACRONYMS
]

# Fast lookup: abbr -> entry
ACRONYM_INDEX = {e["abbr"]: e for e in ACRONYMS}


def acronyms_by_category():
    """Return {category_label: [entries...]} in ACRONYM_CATEGORIES order, entries A-Z."""
    out = {}
    for cat_key, label in ACRONYM_CATEGORIES.items():
        items = sorted([e for e in ACRONYMS if e["cat"] == cat_key], key=lambda e: e["abbr"].lower())
        if items:
            out[label] = items
    return out
