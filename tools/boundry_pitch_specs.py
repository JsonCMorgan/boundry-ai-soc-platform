"""Pitch deck targets and Ollama briefs (Boundry Pitch Quiz)."""

from __future__ import annotations

TARGET_MCQ_PER_DECK = 16
TARGET_FLASH_PER_DECK = 4

DECK_BRIEFS: dict[str, str] = {
    "elevator": (
        "Boundry.AI one-liner, offline-first privacy, SMB MSSP story, pre-revenue honest scale, "
        "what not to claim in interviews, Jason builds Flask command center vs separate marketing tools."
    ),
    "live": (
        "SIEM ingest (windows events, firewall, syslog, Flask middleware, vpn_monitor), severities, "
        "Control Room, SPL-lite over SQLite, Splunk HEC forwarder optional, NordVPN local state alerts."
    ),
    "mssp": (
        "Client retainer workflow, soc_cases ticket_no BT-YYYY-####, dispositions, password spray triage, "
        "weekly SIEM report skill, fictional practice tenants Contoso/NorthPeak/Harbor, analyst notes."
    ),
    "career": (
        "Career Hub: Interview Gym guided/coached/live, hire labs (KQL/SPL, email headers, EDR sim), "
        "Security+ original lessons not dumps, Live vs Practice SIEM data, Messer private layer optional."
    ),
    "tech": (
        "Engineering: Ollama first Anthropic fallback, SQLite/PH pattern, bai PowerShell module, SOAR approve "
        "gates, background SIEM threads, offline-first, no silent cloud of client data."
    ),
    "recruiter": (
        "Resume framing for junior SOC: portfolio lab not fake enterprise MSSP, ISC2 CC and cert path honesty, "
        "interview stories using fictional shift scenarios not real client names, transfer learning from local labs."
    ),
}

BANNED_TERMS = ("cannabis", "dispensary", "marijuana", "weed")