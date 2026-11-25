"""
Central registry for stacked Writing Coach panels (persistent rubrics above textareas).

Never put multi-item rubrics in HTML placeholders.
"""

from __future__ import annotations

from typing import Any

CoachDef = dict[str, Any]

COACHES: dict[str, CoachDef] = {
    "report_investigation": {
        "title": "Include in your investigation notes",
        "tip": "Write this before you read the AI report below. IOC means indicator of compromise: a clue like an IP or username.",
        "items": [
            "What happened (timeline in plain English)",
            "MITRE ATT&CK technique ID or name if you know it",
            "Did the attack succeed? (yes/no and evidence)",
            "IOCs: IP, username, payload, or file hash you would track",
            "Your recommendation (contain, monitor, escalate, or close as FP)",
        ],
        "placeholder_example": "e.g. Multiple 4625 failures from 203.0.113.10, then one 4624…",
    },
    "soc_work_note": {
        "title": "Work note checklist",
        "tip": "Work notes are the ticket timeline. Future you (or Tier 2) reads this.",
        "items": [
            "What you checked (SIEM, enrich, related events)",
            "What you decided and why",
            "What is still open or waiting on someone else",
        ],
        "placeholder_example": "e.g. Enriched src IP — suspicious stub; no successful logon yet…",
    },
    "soc_handoff": {
        "title": "Shift handoff checklist",
        "tip": "Handoff is what the next analyst needs in the first 60 seconds.",
        "items": [
            "What you closed (and disposition: TP / FP)",
            "What stays open (ticket numbers or clients)",
            "Next action and SLA risk",
            "Anything waiting on client or IR",
        ],
        "placeholder_example": "e.g. Closed 2 FP firewall noise. Open: Harbor HIGH spray — verify MFA…",
    },
    "soc_escalate": {
        "title": "Escalation note checklist",
        "items": [
            "Why this is beyond Tier 1 (impact or uncertainty)",
            "Evidence cited (IOCs, events, enrich)",
            "What you already tried",
            "Who should pick it up (IR, senior, client)",
        ],
        "placeholder_example": "e.g. Escalate to Tier 2: ransomware indicators on Harbor host…",
    },
    "siem_fp_resolve": {
        "title": "Document why this is a false positive",
        "items": [
            "Root cause (scanner, test, known benign tool)",
            "Evidence (source IP, schedule, owner if known)",
            "Suppression or tuning you recommend",
        ],
        "placeholder_example": "e.g. Internal vuln scan — added source to allowlist…",
    },
    "daily_log_note": {
        "title": "Daily log entry",
        "items": [
            "What you worked on today (ops or build)",
            "Blockers or decisions needed",
            "What carries to tomorrow",
        ],
        "placeholder_example": "e.g. SIEM tuning + Sec+ Domain 2 review…",
    },
    "training_iocs": {
        "title": "List the IOCs you can support",
        "tip": "IOC = indicator of compromise: IP, user, hash, domain, or pattern in logs.",
        "items": [
            "Attacker or suspicious IP addresses",
            "Usernames or accounts involved",
            "Payloads, commands, or file indicators",
            "Timestamps or event patterns that matter",
        ],
        "placeholder_example": "e.g. Src 198.51.100.77, user admin, PowerShell -enc…",
    },
    "training_response": {
        "title": "Immediate response actions",
        "items": [
            "Containment first (block, isolate, disable) if warranted",
            "Escalation path if impact is unclear",
            "Evidence to preserve before changes",
            "What you would verify next",
        ],
        "placeholder_example": "e.g. Block IP at edge, force password reset for targeted accounts…",
    },
    "career_intel_note": {
        "title": "Enrichment ticket note",
        "items": [
            "What IOC you looked up (IP, domain, or hash)",
            "Verdict from enrich (or unknown)",
            "Recommendation (monitor, block, escalate)",
        ],
        "placeholder_example": "e.g. Looked up 203.0.113.88 — malicious stub — block egress…",
    },
    "career_automation_note": {
        "title": "Automation case note",
        "items": [
            "Client tag",
            "IOC or trigger",
            "Action taken or proposed",
            "Next step",
        ],
        "placeholder_example": "e.g. [Harbor] IOC 203.0.113.44 → approved 24h block…",
    },
    "career_comms_draft": {
        "title": "Stakeholder note",
        "items": [
            "Audience (exec, IT, client contact)",
            "Facts only (what happened, impact)",
            "Clear ask or next step",
            "Tone: calm, no jargon without definition",
        ],
        "placeholder_example": "e.g. Summary for IT lead: suspicious sign-ins contained…",
    },
    "career_soar_reason": {
        "title": "Approve or deny — justify",
        "items": [
            "Risk if you approve (blast radius)",
            "Risk if you deny (exposure time)",
            "Policy or playbook alignment",
        ],
        "placeholder_example": "e.g. Deny isolate — production DB host, need change window…",
    },
    "career_email_paste": {
        "title": "Email / header analysis",
        "items": [
            "Paste full headers or .eml (not just the body snippet)",
            "Note From / Reply-To / Return-Path mismatch",
            "URLs or attachments you would investigate",
        ],
        "placeholder_example": "Paste headers here…",
    },
    "portfolio_what": {
        "title": "What happened (facts)",
        "items": [
            "Name the alert or finding in plain words",
            "List 1–3 log or console facts (user, IP, count, time)",
            "Fictional client name and severity if you have one",
        ],
        "placeholder_example": "e.g. 4625 failures from 203.0.113.44 against Contoso VPN in 15 minutes…",
    },
    "portfolio_why": {
        "title": "Why it matters",
        "items": [
            "Worst case if you ignored it (data, account, or service)",
            "One line on why this is not a routine false positive",
        ],
        "placeholder_example": "e.g. Success would open VPN to internal file share…",
    },
    "portfolio_next": {
        "title": "Next steps",
        "items": [
            "Block, reset, escalate, or monitor (pick one path)",
            "Who gets the handoff (Tier-2, client IT, or closed by you)",
        ],
        "placeholder_example": "e.g. Escalate to Tier-2 with IP block request; watch auth logs 24h…",
    },
    "interview_answer": {
        "title": "Interview answer (STAR-lite)",
        "items": [
            "Situation: one sentence context",
            "Task: what you were responsible for",
            "Action: what you did (tools ok)",
            "Result: outcome or learning",
        ],
        "placeholder_example": "e.g. On a SOC shift I saw…",
    },
    "spl_syntax": {
        "title": "SPL-lite pipeline",
        "tip": "Filters first, then pipes. Boundry supports a subset of Splunk SPL.",
        "items": [
            "1) Filter: field=value, earliest=-24h",
            "2) | stats count by field",
            "3) | sort, | head, | table, | dedup, | where",
        ],
        "placeholder_example": "severity=HIGH earliest=-24h | stats count by src_ip",
    },
    "kql_syntax": {
        "title": "KQL-style query",
        "items": [
            "Start with table: SigninLogs, DeviceEvents, etc.",
            "Filter: | where TimeGenerated > ago(24h)",
            "Project or summarize fields you need",
        ],
        "placeholder_example": "SigninLogs | where ResultType != 0",
    },
    "career_spl_practice": {
        "title": "SPL practice answer",
        "items": [
            "1) Search filters (fields + time)",
            "2) earliest= / latest= if needed",
            "3) | stats / sort / head as the question asks",
        ],
        "placeholder_example": "index=* src_ip=\"10.0.0.5\" earliest=-1h | stats count",
    },
    "secplus_teach_back_practice": {
        "title": "Practice teaching this lesson (optional)",
        "tip": "Read your script aloud. If you stumble, fix the lesson notes, not the jargon.",
        "items": [
            "Did you define three terms before using them?",
            "Did you give one desk or SOC example?",
            "Did you name one exam trap (near-miss wrong answer)?",
        ],
        "placeholder_example": "e.g. A control's function is the job it does…",
    },
    "career_tutor_ask": {
        "title": "Ask the tutor clearly",
        "items": [
            "Name the scenario or lesson section",
            "Say what you tried and where you are stuck",
            "Ask one focused question (not a whole exam dump)",
        ],
        "placeholder_example": "e.g. In the password spray lesson I do not understand why…",
    },
    "ticket_what_happened": {
        "title": "What happened",
        "items": ["Alert source and type", "Who/what is affected", "Time window if known"],
        "placeholder_example": "e.g. Password spray from one IP against many users…",
    },
    "ticket_evidence": {
        "title": "Evidence / IOC",
        "items": ["Primary IOC with enrich result", "Supporting events or fields", "Link to SIEM pivot if any"],
        "placeholder_example": "e.g. IOC 203.0.113.44 — suspicious; 40 failed logons…",
    },
    "ticket_actions_taken": {
        "title": "Actions taken",
        "items": ["What you approved, denied, or executed", "SOAR or manual steps"],
        "placeholder_example": "e.g. Approved edge block; denied host isolate…",
    },
    "ticket_next_action": {
        "title": "Next action",
        "items": ["Owner (you, IR, client)", "Concrete next step", "Time sensitivity"],
        "placeholder_example": "e.g. Monitor 24h for successful logon; escalate if any…",
    },
}


def get_coach(coach_id: str) -> CoachDef | None:
    """Return coach definition or None."""
    return COACHES.get((coach_id or "").strip())


def coach_for_field(field_id: str) -> CoachDef | None:
    """Map ticket field ids to coach registry."""
    mapping = {
        "what_happened": "ticket_what_happened",
        "evidence": "ticket_evidence",
        "actions_taken": "ticket_actions_taken",
        "next_action": "ticket_next_action",
    }
    cid = mapping.get(field_id or "")
    return get_coach(cid) if cid else None
