"""
CISSP concept visuals — Approach B1 (keyword-matched diagram pack).

Matches question/scenario text to a reusable concept diagram so the learner
sees what the question is talking about before answering.

Approach A (Boundry UI mocks) was tried and rejected — kept out of the UI path.
Future B2: swap diagram_id for a static PNG under static/cissp_visuals/.
"""

from __future__ import annotations

from typing import Any

# Each concept: diagram_id drives the frontend SVG; keywords are lowercased
# substrings scored by length (longer / more specific wins).
CISSP_CONCEPTS: list[dict[str, Any]] = [
    {
        "diagram_id": "cia_triad",
        "title": "CIA Triad",
        "caption": "Confidentiality = who can see it. Integrity = who can change it. Availability = can you use it when needed.",
        "keywords": ["cia triad", "confidentiality", "integrity", "availability", "cia"],
        "accent": "#00ff88",
    },
    {
        "diagram_id": "risk",
        "title": "Risk = Threat × Vulnerability × Impact",
        "caption": "A threat needs a weakness and something valuable to hurt. Controls reduce likelihood or impact; residual risk remains.",
        "keywords": [
            "residual risk", "risk appetite", "risk tolerance", "risk assessment",
            "threat actor", "vulnerability", "likelihood", "ale", "sle", "ef", "aro",
            "risk management", "risk",
        ],
        "accent": "#ff8c00",
    },
    {
        "diagram_id": "policy_stack",
        "title": "Policy → Standards → Procedures → Guidelines",
        "caption": "Policy = mandatory intent. Standards = required specifics. Procedures = how-to steps. Guidelines = recommended advice.",
        "keywords": ["security policy", "standard", "procedure", "guideline", "governance", "charter"],
        "accent": "#9944ee",
    },
    {
        "diagram_id": "classification",
        "title": "Data classification & labeling",
        "caption": "Label drives handling: who can read it, where it can live, and how it must be destroyed.",
        "keywords": [
            "data classification", "classification", "top secret", "secret",
            "confidential", "restricted", "labeling", "marking",
        ],
        "accent": "#9944ee",
    },
    {
        "diagram_id": "asset_lifecycle",
        "title": "Asset / data lifecycle",
        "caption": "Create → Store → Use → Share → Archive → Destroy. Security controls change at each stage.",
        "keywords": [
            "asset lifecycle", "data lifecycle", "retention", "sanitization",
            "destruction", "degauss", "dispose", "archive",
        ],
        "accent": "#9944ee",
    },
    {
        "diagram_id": "pki",
        "title": "PKI / certificate trust chain",
        "caption": "CA signs a certificate binding a public key to an identity. You trust the subject because you trust the CA.",
        "keywords": [
            "public key infrastructure", "x.509", "certificate authority",
            "certificate", "pki", "ca ", " root ca", "intermediate ca",
            "public key", "private key", "digital signature",
        ],
        "accent": "#cc6600",
    },
    {
        "diagram_id": "crypto_types",
        "title": "Symmetric vs asymmetric crypto",
        "caption": "Symmetric (AES): same shared key — fast. Asymmetric (RSA/ECC): key pair — slow, great for key exchange & signatures.",
        "keywords": [
            "symmetric", "asymmetric", "aes", "rsa", "ecc", "diffie-hellman",
            "shared secret", "key exchange", "encryption algorithm",
        ],
        "accent": "#cc6600",
    },
    {
        "diagram_id": "hashing",
        "title": "Hashing vs encryption",
        "caption": "Hash = one-way fingerprint (integrity). Encryption = reversible with a key (confidentiality).",
        "keywords": ["hashing", "hash", "sha-256", "sha256", "md5", "hmac", "checksum", "integrity check"],
        "accent": "#cc6600",
    },
    {
        "diagram_id": "security_models",
        "title": "Mandatory access models",
        "caption": "Bell-LaPadula = no read up / no write down (confidentiality). Biba = no read down / no write up (integrity).",
        "keywords": [
            "bell-lapadula", "bell lapadula", "biba", "clark-wilson",
            "lattice", "security model", "no read up", "no write down",
        ],
        "accent": "#cc6600",
    },
    {
        "diagram_id": "defense_in_depth",
        "title": "Defense in depth",
        "accent": "#00d4ff",
        "caption": "Multiple independent layers — if one fails, others still slow or stop the attacker.",
        "keywords": ["defense in depth", "layered security", "layered defense", "defence in depth"],
    },
    {
        "diagram_id": "firewall_ids",
        "title": "Firewall vs IDS / IPS",
        "caption": "Firewall = allow/deny by policy (gate). IDS = detect & alert. IPS = detect & block inline.",
        "keywords": [
            "next-generation firewall", "packet filter", "firewall",
            "intrusion detection", "intrusion prevention", "ids", "ips", "ngfw",
        ],
        "accent": "#00d4ff",
    },
    {
        "diagram_id": "vpn",
        "title": "VPN tunnel",
        "caption": "Encrypted tunnel across an untrusted network so traffic looks private end-to-end.",
        "keywords": ["ipsec", "wireguard", "openvpn", "vpn", "tunnel", "remote access"],
        "accent": "#00d4ff",
    },
    {
        "diagram_id": "osi",
        "title": "OSI / network layers (simplified)",
        "caption": "Attacks and controls map to layers — e.g. MAC spoofing (L2), IP spoofing (L3), TLS (L4–7).",
        "keywords": ["osi model", "osi", "tcp/ip", "layer 2", "layer 3", "layer 4", "network layer"],
        "accent": "#00d4ff",
    },
    {
        "diagram_id": "mfa",
        "title": "Multi-factor authentication",
        "caption": "Something you know + have + are. MFA fails when factors are the same type (password + security question).",
        "keywords": [
            "multi-factor", "multifactor", "two-factor", "2fa", "mfa",
            "something you know", "something you have", "something you are",
            "authenticator", "otp",
        ],
        "accent": "#ff8833",
    },
    {
        "diagram_id": "federation",
        "title": "SSO / federation",
        "caption": "Identity provider authenticates once; service providers trust that assertion (SAML / OAuth / OIDC).",
        "keywords": ["single sign-on", "sso", "saml", "oauth", "openid", "oidc", "federation", "kerberos", "idp"],
        "accent": "#ff8833",
    },
    {
        "diagram_id": "access_control",
        "title": "Access control models",
        "caption": "DAC = owner decides. MAC = labels/clearance. RBAC = role. Least privilege + need-to-know limit blast radius.",
        "keywords": [
            "least privilege", "need to know", "need-to-know", "rbac", "abac",
            "mandatory access", "discretionary access", "dac", "mac", "role-based",
        ],
        "accent": "#ff8833",
    },
    {
        "diagram_id": "auth_attacks",
        "title": "Credential attacks",
        "caption": "Brute force = many passwords, one account. Spray = one password, many accounts. Stuffing = reused breach creds.",
        "keywords": [
            "password spray", "credential stuffing", "brute force", "brute-force",
            "credential", "failed logon", "account lockout",
        ],
        "accent": "#ff8833",
    },
    {
        "diagram_id": "vuln_vs_pentest",
        "title": "Vulnerability scan vs penetration test",
        "caption": "Scan = automated findings list. Pen test = human proves exploitability and business impact.",
        "keywords": [
            "penetration test", "pen test", "pentest", "vulnerability scan",
            "vulnerability assessment", "red team", "purple team",
        ],
        "accent": "#44aaee",
    },
    {
        "diagram_id": "audit",
        "title": "Audit & evidence",
        "caption": "Auditor asks: what should be true? What evidence proves it? Gaps become findings.",
        "keywords": ["security audit", "auditor", "audit", "attestation", "soc 2", "evidence"],
        "accent": "#44aaee",
    },
    {
        "diagram_id": "ir_lifecycle",
        "title": "Incident response lifecycle",
        "caption": "Prepare → Detect/Analyze → Contain → Eradicate → Recover → Lessons learned. Order matters on the exam.",
        "keywords": [
            "incident response", "containment", "eradication", "lessons learned",
            "ir plan", "incident handling", "csirt",
        ],
        "accent": "#ff9900",
    },
    {
        "diagram_id": "siem",
        "title": "SIEM correlation",
        "caption": "Many log sources → normalize → correlate into one alert that means something an analyst can act on.",
        "keywords": ["correlation rule", "siem", "soc analyst", "ioc", "indicator of compromise", "log aggregation"],
        "accent": "#ff9900",
    },
    {
        "diagram_id": "bcdr",
        "title": "BCP / DR — RTO & RPO",
        "caption": "RTO = how fast systems must return. RPO = how much data loss is acceptable (time since last good backup).",
        "keywords": [
            "business continuity", "disaster recovery", "rto", "rpo",
            "bcp", "drp", "hot site", "warm site", "cold site", "backup",
        ],
        "accent": "#ff9900",
    },
    {
        "diagram_id": "owasp",
        "title": "App attacks (OWASP-style)",
        "caption": "Untrusted input reaches the app → injection / XSS / CSRF. Fix = validate, encode, parameterize, tokens.",
        "keywords": [
            "owasp", "sql injection", "sqli", "cross-site scripting", "xss",
            "csrf", "cross-site request", "injection", "insecure direct object",
        ],
        "accent": "#00b432",
    },
    {
        "diagram_id": "sdlc",
        "title": "Secure SDLC",
        "caption": "Security is cheapest early: requirements → design → code → test → deploy → maintain — not bolted on at the end.",
        "keywords": [
            "secure sdlc", "sdlc", "devsecops", "secure coding", "code review",
            "threat modeling", "shift left",
        ],
        "accent": "#00b432",
    },
    {
        "diagram_id": "change_mgmt",
        "title": "Change management",
        "caption": "Request → Review/Approve → Test → Implement → Verify. Untracked changes break availability and auditability.",
        "keywords": ["change management", "change control", "cab", "change advisory"],
        "accent": "#00b432",
    },
    {
        "diagram_id": "encryption_states",
        "title": "Data in transit vs at rest",
        "caption": "In transit = protect on the wire (TLS/VPN). At rest = protect on disk/DB (AES, full-disk, column encryption).",
        "keywords": [
            "encryption at rest", "at rest", "in transit", "in motion",
            "tls", "full disk", "bitlocker", "transparent data encryption",
        ],
        "accent": "#cc6600",
    },
    {
        "diagram_id": "physical",
        "title": "Physical security layers",
        "caption": "Deter → Delay → Detect → Respond. Badges, mantraps, cameras, and guards are still CISSP material.",
        "keywords": ["mantrap", "physical security", "badge", "cctv", "tailgating", "data center"],
        "accent": "#7a9ab0",
    },
    {
        "diagram_id": "cloud_shared",
        "title": "Cloud shared responsibility",
        "caption": "Provider secures the cloud; you secure what’s in it. The split changes for IaaS vs PaaS vs SaaS.",
        "keywords": [
            "shared responsibility", "iaas", "paas", "saas",
            "cloud provider", "hyperscaler",
        ],
        "accent": "#44aaee",
    },
]

# When no keyword hits, show a domain-level default concept.
_DOMAIN_FALLBACK: dict[int, str] = {
    1: "risk",
    2: "classification",
    3: "crypto_types",
    4: "firewall_ids",
    5: "mfa",
    6: "vuln_vs_pentest",
    7: "ir_lifecycle",
    8: "owasp",
}

_CONCEPT_BY_ID: dict[str, dict[str, Any]] = {c["diagram_id"]: c for c in CISSP_CONCEPTS}


def _match_concept(text: str) -> dict[str, Any] | None:
    """Score keyword hits; prefer longer/more specific matches."""
    blob = (text or "").lower()
    if not blob.strip():
        return None
    best: dict[str, Any] | None = None
    best_score = 0
    for concept in CISSP_CONCEPTS:
        score = 0
        for kw in concept["keywords"]:
            k = kw.lower().strip()
            if k and k in blob:
                # Longer phrases outweigh short ambiguous tokens like "risk"/"ca "
                score += max(3, len(k))
        if score > best_score:
            best_score = score
            best = concept
    return best if best_score > 0 else None


def get_cissp_visual(
    domain_num: int,
    scenario: str = "",
    question: str = "",
) -> dict[str, Any] | None:
    """Return a concept-diagram payload matched to the question text."""
    combined = f"{scenario}\n{question}"
    concept = _match_concept(combined)
    matched = concept is not None
    if not concept:
        fallback_id = _DOMAIN_FALLBACK.get(domain_num, "risk")
        concept = _CONCEPT_BY_ID.get(fallback_id)
    if not concept:
        return None
    return {
        "domain_num": domain_num,
        "diagram_id": concept["diagram_id"],
        "title": concept["title"],
        "caption": concept["caption"],
        "accent": concept["accent"],
        "matched": matched,
        "mode": "concept",
        "label": "Concept demo" if matched else "Domain concept",
    }
