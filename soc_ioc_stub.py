"""
Live ops IOC enrichment stub (offline, no cloud).

Used by SOC Floor /soc enrich API. Career intel lab may extend the same table locally;
this module keeps GitHub clones working without publishing career_lab content.
"""

from __future__ import annotations

import re
from typing import Any

# Local reputation table (offline stub). Keys normalized lowercase.
REPUTATION: dict[str, dict[str, Any]] = {
    "203.0.113.88": {
        "ioc_type": "ip",
        "verdict": "malicious",
        "score": 92,
        "tags": ["c2", "malware_hosting"],
        "geo": "Documentation range (TEST-NET-3)",
        "summary": "Known in Boundry stub as a download/C2 host used in EDR lab samples.",
        "first_seen": "2026-08-12",
    },
    "198.51.100.77": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 68,
        "tags": ["scanner", "rare_port"],
        "geo": "Documentation range (TEST-NET-2)",
        "summary": "Seen in stub as destination for odd egress (port 4444). Not confirmed malware alone.",
        "first_seen": "2026-09-01",
    },
    "8.8.8.8": {
        "ioc_type": "ip",
        "verdict": "benign",
        "score": 5,
        "tags": ["public_dns"],
        "geo": "Public DNS",
        "summary": "Well-known public DNS resolver. Not a reason to escalate by itself.",
        "first_seen": "n/a",
    },
    "192.0.2.55": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 72,
        "tags": ["test_net", "sql_injection_sim"],
        "geo": "Documentation range (TEST-NET-1)",
        "summary": "Boundry stub: seen in simulated web SQL injection alerts (administrator user). Validate in app logs; block only per policy.",
        "first_seen": "2026-10-01",
    },
    "c0ntoso-finance.com": {
        "ioc_type": "domain",
        "verdict": "malicious",
        "score": 88,
        "tags": ["lookalike", "phishing"],
        "geo": "n/a",
        "summary": "Lookalike of contoso.com used in Boundry BEC / proxy drills. Treat as phishing infrastructure.",
        "first_seen": "2026-09-20",
    },
    "login.microsoftonline.com": {
        "ioc_type": "domain",
        "verdict": "benign",
        "score": 2,
        "tags": ["microsoft", "auth"],
        "geo": "n/a",
        "summary": "Legitimate Microsoft sign-in host. Do not block as phishing without other evidence.",
        "first_seen": "n/a",
    },
    "a3f5c8e1b2d9470f6e4a1c9b8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e": {
        "ioc_type": "hash",
        "verdict": "malicious",
        "score": 95,
        "tags": ["trojan", "powershell_dropper"],
        "geo": "n/a",
        "summary": "Stub SHA-256 for a Boundry practice dropper. Escalate and preserve the sample path.",
        "first_seen": "2026-07-04",
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "ioc_type": "hash",
        "verdict": "benign",
        "score": 0,
        "tags": ["empty_file"],
        "geo": "n/a",
        "summary": "SHA-256 of empty file. Benign hash; check why it appeared in the alert.",
        "first_seen": "n/a",
    },
    "micr0soft-secure.com": {
        "ioc_type": "domain",
        "verdict": "malicious",
        "score": 90,
        "tags": ["credential_harvest", "lookalike"],
        "geo": "n/a",
        "summary": "Lookalike Microsoft login host used in Boundry credential-harvest drills.",
        "first_seen": "2026-10-01",
    },
    "198.51.100.200": {
        "ioc_type": "ip",
        "verdict": "suspicious",
        "score": 55,
        "tags": ["vpn_exit", "shared"],
        "geo": "Documentation range (TEST-NET-2)",
        "summary": "Shared VPN exit stub. Suspicious only with other signals; not enough alone to declare malware.",
        "first_seen": "2026-09-15",
    },
    "update.microsoft.com": {
        "ioc_type": "domain",
        "verdict": "benign",
        "score": 1,
        "tags": ["microsoft", "patch"],
        "geo": "n/a",
        "summary": "Legitimate Microsoft update host. Do not escalate solely because a host contacted it.",
        "first_seen": "n/a",
    },
}


def normalize_ioc(value: str) -> str:
    """Normalize IOC for stub lookup."""
    v = (value or "").strip().lower()
    v = v.removeprefix("http://").removeprefix("https://")
    v = v.split("/")[0]
    return v


def lookup_ioc(value: str) -> dict[str, Any]:
    """Local reputation lookup. Never calls the internet."""
    key = normalize_ioc(value)
    if not key:
        return {"ok": False, "error": "Enter an IP, domain, or SHA-256 hash."}
    row = REPUTATION.get(key)
    if not row:
        ioc_type = "unknown"
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", key):
            ioc_type = "ip"
        elif re.fullmatch(r"[a-f0-9]{64}", key):
            ioc_type = "hash"
        elif "." in key:
            ioc_type = "domain"
        return {
            "ok": True,
            "found": False,
            "ioc": key,
            "ioc_type": ioc_type,
            "verdict": "unknown",
            "score": None,
            "tags": [],
            "geo": "n/a",
            "summary": "No stub record. In a real SOC you would try a second source and still document 'unknown'.",
            "first_seen": "n/a",
        }
    return {
        "ok": True,
        "found": True,
        "ioc": key,
        **row,
    }
