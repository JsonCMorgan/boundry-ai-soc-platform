"""
GTA SOC Career Lab — skill tracks, portfolio evidence, shift simulator.

Target: hire-ready SOC Analyst reps (triage volume, SIEM/IR/MITRE/notes).
Shift modes: Quick (15–20 min default) and Standard (45–60 min).
"""

from __future__ import annotations

import json
import random
from datetime import datetime
from typing import Any

# ── Weekly "Today's drill" (Career Hub) ───────────────────────────────────────
# weekday keys match datetime.weekday(): Mon=0 … Sun=6 (machine local time).
WEEKLY_DRILL_PLAN: list[dict[str, Any]] = [
    {
        "weekday": 0,
        "day_name": "Monday",
        "title": "SPL lesson + practice + queries",
        "duration": "~45–60m",
        "bullets": [
            "Complete one SPL Learn lesson and its practice set.",
            "Run a few live queries in SIEM Query to lock the syntax in.",
            "Note one query pattern you'd explain in an interview.",
        ],
        "ctas": [
            {"label": "SPL Learn", "href": "/career/spl"},
            {"label": "SIEM Query", "href": "/siem/query"},
        ],
    },
    {
        "weekday": 1,
        "day_name": "Tuesday",
        "title": "Interview Gym — Guided ×2 → Coached ×1",
        "duration": "~45–60m",
        "bullets": [
            "Two Guided scenarios to warm up the talk-track.",
            "One Coached run — tighten structure and MITRE language.",
            "Skip Live today; save the timer for Thursday/Saturday.",
        ],
        "ctas": [
            {"label": "Interview Gym", "href": "/career/interview"},
        ],
    },
    {
        "weekday": 2,
        "day_name": "Wednesday",
        "title": "Shift reps → portfolio evidence",
        "duration": "~45–60m",
        "bullets": [
            "Quick Shift for daily volume, or Standard if you have the hour.",
            "Bank one clean write-up into Portfolio after the shift.",
            "Tag MITRE where it belongs — interview gold.",
        ],
        "ctas": [
            {"label": "Start Shift", "href": "/career/shift"},
            {"label": "Portfolio", "href": "/career/portfolio"},
        ],
    },
    {
        "weekday": 3,
        "day_name": "Thursday",
        "title": "KQL Learn + Interview Live ×1",
        "duration": "~45–60m",
        "bullets": [
            "One KQL Learn lesson + practice (Sentinel mental model).",
            "Then one Interview Gym Live timed run — say it out loud.",
            "Optional outside: short EDR lab (Defender / CrowdStrike trail) if time remains.",
        ],
        "outside_tip": "Optional: vendor EDR lab or Microsoft Learn Defender path — Hub deliverables are KQL + Live.",
        "ctas": [
            {"label": "KQL Learn", "href": "/career/kql"},
            {"label": "Interview Live", "href": "/career/interview"},
        ],
    },
    {
        "weekday": 4,
        "day_name": "Friday",
        "title": "Training scenario OR SOAR + write-up",
        "duration": "~45–60m",
        "bullets": [
            "Pick one: a Training scenario chain, or SOAR queue practice.",
            "Finish with one write-up — Portfolio case or Reports note.",
            "Close the week with evidence, not just reps.",
        ],
        "ctas": [
            {"label": "Training", "href": "/training"},
            {"label": "SOAR", "href": "/soar"},
            {"label": "Portfolio", "href": "/career/portfolio"},
            {"label": "Reports", "href": "/reports"},
        ],
    },
    {
        "weekday": 5,
        "day_name": "Saturday",
        "title": "Portfolio polish + weakest Interview Live",
        "duration": "~45–60m",
        "bullets": [
            "Polish Portfolio cases — clarity, MITRE, outcome.",
            "Re-run your weakest Interview scenario in Live mode.",
            "Optional: one Security+ domain (Show me → Prove it) if a gate is still open.",
        ],
        "ctas": [
            {"label": "Portfolio", "href": "/career/portfolio"},
            {"label": "Interview Gym", "href": "/career/interview"},
            {"label": "Security+ Lab", "href": "/career/secplus"},
            {"label": "CISSP Hub", "href": "/cissp"},
        ],
    },
    {
        "weekday": 6,
        "day_name": "Sunday",
        "title": "Rest day — or light glossary quiz",
        "duration": "~0–20m",
        "bullets": [
            "Default: rest. Recovery beats burnout for interview prep.",
            "Optional: a short Glossary quiz if you want a light touch.",
            "Peek Monday's plan so Monday morning is frictionless.",
        ],
        "ctas": [
            {"label": "Glossary quiz", "href": "/glossary"},
        ],
    },
]


def get_week_plan() -> list[dict[str, Any]]:
    """Return the full Mon–Sun Career Hub drill plan (copy-safe list)."""
    return list(WEEKLY_DRILL_PLAN)


def get_today_drill(now: datetime | None = None) -> dict[str, Any]:
    """
    Return today's drill for the Career Hub.

    Uses machine-local weekday (datetime.weekday: Mon=0 … Sun=6).
    Optional `now` is for tests / forced day.
    """
    when = now or datetime.now()
    day = when.weekday()
    for plan in WEEKLY_DRILL_PLAN:
        if plan["weekday"] == day:
            return dict(plan)
    # Unreachable unless plan is corrupted — fall back to Monday
    return dict(WEEKLY_DRILL_PLAN[0])


def point_saturday_secplus_cta(
    drill: dict[str, Any],
    weak_lesson_id: str | None = None,
) -> dict[str, Any]:
    """
    Keep Saturday portfolio-first. Point Sec+ CTA at Continue next micro-lesson.
    """
    out = dict(drill)
    if out.get("weekday") != 5:
        return out
    href = (
        f"/career/secplus/lesson/{weak_lesson_id}"
        if weak_lesson_id
        else "/career/secplus"
    )
    label = "Sec+ Continue lesson" if weak_lesson_id else "Security+ Lab"
    ctas = []
    for cta in list(out.get("ctas") or []):
        if str(cta.get("href") or "").startswith("/career/secplus"):
            ctas.append({"label": label, "href": href})
        else:
            ctas.append(dict(cta))
    out["ctas"] = ctas
    return out


# ── Prove-it gates (hire-stack targets) ───────────────────────────────────────
# Soft progress UI on Career Hub — not hard locks.
PROVE_IT_TARGETS: dict[str, int] = {
    "shifts": 10,
    "portfolio": 5,
    "interview_scenarios": 8,  # all through Live
}

TICKET_HYGIENE_TEMPLATE = (
    "Subject: \n"
    "What: \n"
    "Why: \n"
    "Disposition: \n"
    "MITRE: \n"
    "Next: "
)

APPLICATION_FRAMING = (
    "I built an offline SOC lab (SIEM, triage shifts, IR notes, MITRE tagging) and "
    "practice interview walkthroughs weekly. Portfolio cases below are real lab "
    "investigations with disposition and MITRE — happy to walk any of them live."
)


def format_ticket_summary(
    *,
    what: str = "",
    why: str = "",
    disposition: str = "",
    mitre: str = "",
    next_steps: str = "",
) -> str:
    """Compose labeled ticket-hygiene fields into a paste-ready summary body."""
    parts = [
        f"What: {(what or '').strip()}",
        f"Why: {(why or '').strip()}",
        f"Disposition: {(disposition or '').strip()}",
        f"MITRE: {(mitre or '').strip()}",
        f"Next: {(next_steps or '').strip()}",
    ]
    return "\n".join(parts)


def build_prove_it_gates(
    *,
    spl_lessons_done: int,
    spl_lessons_total: int,
    spl_quiz_passed: bool,
    kql_lessons_done: int = 0,
    kql_lessons_total: int = 0,
    kql_quiz_passed: bool = False,
    kql_quizzes_done: int = 0,
    kql_quizzes_total: int = 0,
    secplus_lessons_passed: int = 0,
    secplus_lessons_total: int = 0,
    secplus_domains_passed: int = 0,
    secplus_domains_total: int = 0,
    net_lessons_done: int = 0,
    net_lessons_total: int = 0,
    net_quiz_passed: bool = False,
    net_quizzes_done: int = 0,
    net_quizzes_total: int = 0,
    interview_guided: int = 0,
    interview_coached: int = 0,
    interview_live: int = 0,
    interview_total: int = 8,
    shifts_completed: int = 0,
    portfolio_count: int = 0,
    portfolio_with_mitre: int = 0,
) -> list[dict[str, Any]]:
    """
    Soft hire-readiness gates for Career Hub.

    Targets: SPL green (lessons + quiz) → all scenarios Live →
    ≥10 shifts + ≥5 portfolio cases. KQL is a parallel Sentinel gate
    (all lessons + every section quiz ≥70%). Security+ is N/micro-lesson
    quizzes ≥70% (domain green when all lessons in that domain pass).
    Net-for-SOC mirrors KQL: Show-me lessons + every lesson quiz ≥70%.
    """
    spl_need = max(1, spl_lessons_total)
    spl_pct = min(100, round(100 * spl_lessons_done / spl_need))
    spl_done = spl_lessons_done >= spl_need and spl_quiz_passed

    kql_need = max(1, kql_lessons_total) if kql_lessons_total else 1
    kql_quiz_need = max(1, kql_quizzes_total) if kql_quizzes_total else 0
    # Blend lesson + section-quiz progress when quiz totals are known.
    if kql_lessons_total and kql_quizzes_total:
        kql_pct = min(
            100,
            round(
                100
                * (kql_lessons_done + kql_quizzes_done)
                / (kql_need + kql_quiz_need)
            ),
        )
    elif kql_lessons_total:
        kql_pct = min(100, round(100 * kql_lessons_done / kql_need))
    else:
        kql_pct = 0
    kql_done = bool(kql_lessons_total) and kql_lessons_done >= kql_need and kql_quiz_passed

    net_need = max(1, net_lessons_total) if net_lessons_total else 1
    net_quiz_need = max(1, net_quizzes_total) if net_quizzes_total else 0
    if net_lessons_total and net_quizzes_total:
        net_pct = min(
            100,
            round(
                100
                * (net_lessons_done + net_quizzes_done)
                / (net_need + net_quiz_need)
            ),
        )
    elif net_lessons_total:
        net_pct = min(100, round(100 * net_lessons_done / net_need))
    else:
        net_pct = 0
    net_done = bool(net_lessons_total) and net_lessons_done >= net_need and net_quiz_passed

    # Prefer lesson-level gate; fall back to domain counts for older callers.
    if secplus_lessons_total:
        sec_need = max(1, secplus_lessons_total)
        sec_pct = min(100, round(100 * secplus_lessons_passed / sec_need))
        sec_done = secplus_lessons_passed >= sec_need
        sec_detail = (
            f"{secplus_lessons_passed}/{secplus_lessons_total} lessons prove-passed (≥70%)"
        )
        if secplus_domains_total:
            sec_detail += (
                f" · {secplus_domains_passed}/{secplus_domains_total} domains green"
            )
        sec_blurb = "All micro-lessons quiz-passed (≥70% each)"
    elif secplus_domains_total:
        sec_need = max(1, secplus_domains_total)
        sec_pct = min(100, round(100 * secplus_domains_passed / sec_need))
        sec_done = secplus_domains_passed >= sec_need
        sec_detail = (
            f"{secplus_domains_passed}/{secplus_domains_total} domains passed (≥70%)"
        )
        sec_blurb = "All 5 domains quiz-passed (≥70% each)"
    else:
        sec_pct = 0
        sec_done = False
        sec_detail = "Start SY0-701 Show me → Prove it"
        sec_blurb = "All micro-lessons quiz-passed (≥70% each)"

    live_need = interview_total or PROVE_IT_TARGETS["interview_scenarios"]
    live_pct = min(100, round(100 * interview_live / live_need))
    live_done = interview_live >= live_need

    shift_need = PROVE_IT_TARGETS["shifts"]
    shift_pct = min(100, round(100 * shifts_completed / shift_need))
    shift_done = shifts_completed >= shift_need

    port_need = PROVE_IT_TARGETS["portfolio"]
    port_pct = min(100, round(100 * portfolio_count / port_need))
    port_done = portfolio_count >= port_need

    return [
        {
            "id": "spl",
            "label": "SPL Learn",
            "detail": (
                f"{spl_lessons_done}/{spl_lessons_total} lessons"
                + (" · quiz passed" if spl_quiz_passed else " · quiz pending")
            ),
            "href": "/career/spl",
            "pct": 100 if spl_done else spl_pct,
            "done": spl_done,
            "target_blurb": "All lessons + quiz pass",
        },
        {
            "id": "kql",
            "label": "KQL Learn",
            "detail": (
                (
                    f"{kql_lessons_done}/{kql_lessons_total} lessons"
                    + (
                        f" · {kql_quizzes_done}/{kql_quizzes_total} section quizzes"
                        if kql_quizzes_total
                        else (" · quizzes passed" if kql_quiz_passed else " · quizzes pending")
                    )
                )
                if kql_lessons_total
                else "Start the Sentinel track"
            ),
            "href": "/career/kql",
            "pct": 100 if kql_done else kql_pct,
            "done": kql_done,
            "target_blurb": "All lessons + every section quiz ≥70%",
        },
        {
            "id": "secplus",
            "label": "Security+ Lab",
            "detail": sec_detail,
            "href": "/career/secplus",
            "pct": 100 if sec_done else sec_pct,
            "done": sec_done,
            "target_blurb": sec_blurb,
        },
        {
            "id": "net",
            "label": "Net-for-SOC",
            "detail": (
                (
                    f"{net_lessons_done}/{net_lessons_total} lessons"
                    + (
                        f" · {net_quizzes_done}/{net_quizzes_total} lesson quizzes"
                        if net_quizzes_total
                        else (" · quizzes passed" if net_quiz_passed else " · quizzes pending")
                    )
                )
                if net_lessons_total
                else "Start the analyst networking spine"
            ),
            "href": "/career/net",
            "pct": 100 if net_done else net_pct,
            "done": net_done,
            "target_blurb": "All lessons + every lesson quiz ≥70%",
        },
        {
            "id": "interview",
            "label": "Interview Gym",
            "detail": (
                f"Guided {interview_guided}/{live_need} · "
                f"Coached {interview_coached}/{live_need} · "
                f"Live {interview_live}/{live_need}"
            ),
            "href": "/career/interview",
            "pct": 100 if live_done else live_pct,
            "done": live_done,
            "target_blurb": f"All {live_need} scenarios through Live",
        },
        {
            "id": "shifts",
            "label": "Shift reps",
            "detail": f"{shifts_completed}/{shift_need} completed shifts",
            "href": "/career/shift",
            "pct": 100 if shift_done else shift_pct,
            "done": shift_done,
            "target_blurb": f"≥{shift_need} completed shifts",
        },
        {
            "id": "portfolio",
            "label": "Portfolio evidence",
            "detail": (
                f"{portfolio_count}/{port_need} cases"
                + (f" · {portfolio_with_mitre} with MITRE" if portfolio_count else "")
            ),
            "href": "/career/portfolio",
            "pct": 100 if port_done else port_pct,
            "done": port_done,
            "target_blurb": f"≥{port_need} cases (MITRE + disposition)",
        },
    ]


# ── Shift modes ──────────────────────────────────────────────────────────────
# Quick is default so Jason can get reps without blocking an evening.
SHIFT_MODES: dict[str, dict[str, Any]] = {
    "quick": {
        "id": "quick",
        "label": "Quick Shift",
        "minutes": 18,
        "duration_sec": 18 * 60,
        "alert_count": 6,
        "blurb": "15–20 min — multi-client queue, SLA clocks, short case notes. Default for daily reps.",
    },
    "standard": {
        "id": "standard",
        "label": "Standard Shift",
        "minutes": 50,
        "duration_sec": 50 * 60,
        "alert_count": 14,
        "blurb": "45–60 min — deeper multi-tenant queue + fuller IR write-ups when you have time.",
    },
}

# ── Skill tracks (GTA SOC hire path) ─────────────────────────────────────────
SOC_TRACKS: list[dict[str, Any]] = [
    {
        "id": "siem",
        "name": "SIEM Triage",
        "icon": "📡",
        "color": "#00d4ff",
        "goal": "Separate signal from noise fast; write usable notes.",
        "target": 50,  # actions toward "proficient"
        "drills": [
            {"label": "Open SIEM live stream", "href": "/siem"},
            {"label": "Run SPL queries", "href": "/siem/query"},
            {"label": "SPL Learn track", "href": "/career/spl"},
            {"label": "KQL Learn track", "href": "/career/kql"},
            {"label": "Security+ Lab (ops lessons)", "href": "/career/secplus"},
            {"label": "Email Triage Lab", "href": "/career/email"},
            {"label": "Run a Quick Shift", "href": "/career/shift"},
        ],
        "jd_keywords": ["SIEM", "Splunk", "Sentinel", "log analysis", "triage"],
    },
    {
        "id": "ir",
        "name": "Incident Response",
        "icon": "🚨",
        "color": "#ff4444",
        "goal": "Contain → eradicate → recover mindset with clear documentation.",
        "target": 20,
        "drills": [
            {"label": "SOC training scenarios", "href": "/training"},
            {"label": "Security+ Lab (IR / ops)", "href": "/career/secplus"},
            {"label": "Write / review reports", "href": "/reports"},
            {"label": "SOAR queue", "href": "/soar"},
        ],
        "jd_keywords": ["incident response", "containment", "escalation", "playbooks"],
    },
    {
        "id": "mitre",
        "name": "MITRE ATT&CK",
        "icon": "🎯",
        "color": "#ff8c00",
        "goal": "Tag adversary behaviour the way Toronto SOC tickets expect.",
        "target": 15,
        "drills": [
            {"label": "MITRE in training", "href": "/training"},
            {"label": "Practice mapping in shifts", "href": "/career/shift"},
        ],
        "jd_keywords": ["MITRE ATT&CK", "TTPs", "threat hunting"],
    },
    {
        "id": "endpoint",
        "name": "Endpoint / Findings",
        "icon": "💻",
        "color": "#00ff88",
        "goal": "Investigate host findings like EDR tickets (scan → fix → note).",
        "target": 25,
        "drills": [
            {"label": "EDR Console Lab", "href": "/career/edr"},
            {"label": "Scan findings", "href": "/scan/findings"},
            {"label": "Control Room triage", "href": "/control-room"},
        ],
        "jd_keywords": ["EDR", "Defender", "CrowdStrike", "endpoint", "vulnerability"],
    },
    {
        "id": "identity",
        "name": "Identity Attacks",
        "icon": "🔑",
        "color": "#ff8833",
        "goal": "Recognise spray, brute force, and priv-esc patterns.",
        "target": 15,
        "drills": [
            {"label": "SIEM auth events", "href": "/siem"},
            {"label": "Attack simulations", "href": "/control-room"},
        ],
        "jd_keywords": ["identity", "Entra ID", "MFA", "password spray", "brute force"],
    },
    {
        "id": "automation",
        "name": "SOAR / Automation",
        "icon": "⚡",
        "color": "#ff9900",
        "goal": "Approve-gated response — enrichment then contain.",
        "target": 10,
        "drills": [
            {"label": "SOAR incidents", "href": "/soar"},
            {"label": "Playbooks", "href": "/playbooks"},
        ],
        "jd_keywords": ["SOAR", "playbooks", "automation", "Tines"],
    },
    {
        "id": "reporting",
        "name": "Analyst Reporting",
        "icon": "📄",
        "color": "#9944ee",
        "goal": "Clear tickets and client-ready write-ups (interview prop).",
        "target": 15,
        "drills": [
            {"label": "Reports list", "href": "/reports"},
            {"label": "Portfolio export", "href": "/career/portfolio"},
        ],
        "jd_keywords": ["documentation", "ticketing", "communication", "ServiceNow"],
    },
    {
        "id": "interview",
        "name": "Interview Walkthroughs",
        "icon": "🎤",
        "color": "#00d4ff",
        "goal": "Say investigations out loud — Guided wheels first, then Live timer.",
        "target": 24,  # 8 scenarios × Guided+Coached(+Live later)
        "drills": [
            {"label": "Interview Gym", "href": "/career/interview"},
        ],
        "jd_keywords": ["triage", "escalation", "communication", "scenario interview"],
    },
]

# ── MSSP fake clients (G3 multi-tenant queue) ─────────────────────────────────
MSSP_CLIENTS: list[dict[str, str]] = [
    {
        "id": "contoso",
        "name": "Contoso Retail",
        "tier": "Gold",
        "note": "Retail POS + HQ; VIP store managers.",
    },
    {
        "id": "northpeak",
        "name": "NorthPeak Outfitters",
        "tier": "Silver",
        "note": "Outdoor retail chain; strict change windows.",
    },
    {
        "id": "harbor",
        "name": "Harbor Health",
        "tier": "Gold",
        "note": "Clinic network; PHI-sensitive hosts.",
    },
]

_CLIENT_BY_ID = {c["id"]: c for c in MSSP_CLIENTS}


def list_mssp_clients() -> list[dict[str, str]]:
    """Public client list for shift case-console dropdowns."""
    return list(MSSP_CLIENTS)


# ── Alert bank for shift simulator ───────────────────────────────────────────
# disposition: true_positive | false_positive | escalate
# mitre: technique id string (optional)
# client_id: MSSP tenant tag (G3)
# sla_minutes: soft response target from shift start (G2)
_ALERT_BANK: list[dict[str, Any]] = [
    {
        "title": "Multiple failed logons — single account",
        "severity": "HIGH",
        "source": "windows_event / 4625",
        "detail": "47 failed logons for jsmith in 4 minutes from 203.0.113.44. Success (4624) none yet.",
        "disposition": "true_positive",
        "mitre": "T1110.001",
        "hint": "Brute force against one account — lockout / reset / block src.",
        "client_id": "contoso",
        "sla_minutes": 20,
    },
    {
        "title": "Failed logons — same password, many users",
        "severity": "CRITICAL",
        "source": "windows_event / 4625",
        "detail": "Password 'Summer2026!' tried against 30 accounts in 10 minutes from one IP.",
        "disposition": "true_positive",
        "mitre": "T1110.003",
        "hint": "Password spray pattern — block IP, force MFA, hunt successes.",
        "client_id": "northpeak",
        "sla_minutes": 10,
    },
    {
        "title": "Firewall DROP burst on 445",
        "severity": "MEDIUM",
        "source": "firewall",
        "detail": "200+ DROPs to tcp/445 from 198.51.100.9 in 2 minutes. No internal lateral movement seen.",
        "disposition": "true_positive",
        "mitre": "T1021.002",
        "hint": "Internet SMB probe — confirm perimeter block held; note IOC.",
        "client_id": "harbor",
        "sla_minutes": 30,
    },
    {
        "title": "Scheduled Defender scan completed",
        "severity": "INFO",
        "source": "windows_event",
        "detail": "Windows Defender finished a routine quick scan. No threats found. Host: WS-FINANCE-12.",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Benign operational noise — close as FP / expected activity.",
        "client_id": "contoso",
        "sla_minutes": 45,
    },
    {
        "title": "VPN reconnect after expected drop",
        "severity": "LOW",
        "source": "vpn_monitor",
        "detail": "NordLynx briefly Down then Up within 40s during known ISP maintenance window (ticket CHG-441).",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Documented change window — FP unless kill-switch failed.",
        "client_id": "northpeak",
        "sla_minutes": 40,
    },
    {
        "title": "New local admin created overnight",
        "severity": "CRITICAL",
        "source": "windows_event / 4720",
        "detail": "Account 'svc_backup2' added to Administrators at 03:14 by unused service account. No change ticket.",
        "disposition": "escalate",
        "mitre": "T1136.001",
        "hint": "Possible persistence — escalate to IR / isolate host pending review.",
        "client_id": "harbor",
        "sla_minutes": 10,
    },
    {
        "title": "SIEM correlation: brute force threshold",
        "severity": "HIGH",
        "source": "siem_rule",
        "detail": "Rule 'Failed Logon Burst' fired — 12 failures / 60s for one src_ip. Matches known BAD_IP list.",
        "disposition": "true_positive",
        "mitre": "T1110",
        "hint": "Correlated detection — suppress IP, open case, check for 4624 success.",
        "client_id": "contoso",
        "sla_minutes": 15,
    },
    {
        "title": "Employee travel login from new country",
        "severity": "MEDIUM",
        "source": "identity",
        "detail": "User ceo@client.com signed in from Frankfurt. HR confirms CEO is at a conference this week. MFA passed.",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Validate travel; if confirmed, close FP and add location allow note.",
        "client_id": "northpeak",
        "sla_minutes": 25,
    },
    {
        "title": "PowerShell encoded command on workstation",
        "severity": "HIGH",
        "source": "endpoint",
        "detail": "powershell.exe -enc <base64> spawned by excel.exe on WS-HR-03. Parent was email attachment 'Invoice.xlsm'.",
        "disposition": "escalate",
        "mitre": "T1059.001",
        "hint": "Likely malware — isolate host, escalate, preserve evidence.",
        "client_id": "harbor",
        "sla_minutes": 12,
    },
    {
        "title": "Nmap-style port scan from internal jumphost",
        "severity": "MEDIUM",
        "source": "firewall / ids",
        "detail": "Sequential probes 22/80/443/3389 from JUMP-01. Change ticket CHG-512: 'quarterly vuln scan' approved.",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Authorized scan — FP if ticket matches scanner identity.",
        "client_id": "contoso",
        "sla_minutes": 35,
    },
    {
        "title": "RDP from internet to production server",
        "severity": "CRITICAL",
        "source": "firewall",
        "detail": "ALLOW hit: tcp/3389 from 203.0.113.88 → PROD-DC01. Rule looks misconfigured; no VPN.",
        "disposition": "escalate",
        "mitre": "T1021.001",
        "hint": "Exposed RDP — emergency contain, escalate, fix firewall rule.",
        "client_id": "northpeak",
        "sla_minutes": 8,
    },
    {
        "title": "DNS query volume spike — marketing PC",
        "severity": "MEDIUM",
        "source": "dns / proxy",
        "detail": "WS-MKT-07 queried 8k unique domains in 20 min including known DGA-like patterns.",
        "disposition": "true_positive",
        "mitre": "T1071.004",
        "hint": "Possible malware C2 — pull EDR, isolate if confirmed.",
        "client_id": "harbor",
        "sla_minutes": 18,
    },
    {
        "title": "SOAR auto-lockdown after spray",
        "severity": "HIGH",
        "source": "soar",
        "detail": "Playbook locked out 3 accounts after spray detection. One account had a legitimate password change mid-window.",
        "disposition": "escalate",
        "mitre": "T1110.003",
        "hint": "Validate lockdown; restore false victim carefully; escalate edge cases.",
        "client_id": "contoso",
        "sla_minutes": 15,
    },
    {
        "title": "Backup job service account Kerberos errors",
        "severity": "LOW",
        "source": "windows_event",
        "detail": "svc_veeam failed Kerberos pre-auth overnight. Backup still completed via NTLM fallback. Known after patch Tuesday.",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Known post-patch noise if backups healthy — FP with note.",
        "client_id": "northpeak",
        "sla_minutes": 40,
    },
    {
        "title": "Suspicious inbox rule — forward to external Gmail",
        "severity": "HIGH",
        "source": "email / identity",
        "detail": "New inbox rule on cfo@client.com forwards all mail to personal Gmail. Created from IP in Eastern Europe. MFA not prompted (legacy auth).",
        "disposition": "escalate",
        "mitre": "T1114.003",
        "hint": "BEC / mailbox compromise — revoke sessions, remove rule, escalate.",
        "client_id": "harbor",
        "sla_minutes": 12,
    },
    {
        "title": "Nessus scanner authenticated checks",
        "severity": "INFO",
        "source": "vuln_scanner",
        "detail": "Authenticated vulnerability scan from approved scanner IP against subnet 10.0.10.0/24. Ticket SEC-220.",
        "disposition": "false_positive",
        "mitre": "",
        "hint": "Expected scanner traffic — FP.",
        "client_id": "contoso",
        "sla_minutes": 45,
    },
]


def get_shift_mode(mode_id: str) -> dict[str, Any]:
    """Return shift mode config; default Quick."""
    return SHIFT_MODES.get(mode_id, SHIFT_MODES["quick"])


def build_shift_alerts(mode_id: str) -> list[dict[str, Any]]:
    """Pick a shuffled multi-client alert queue sized for the shift mode."""
    mode = get_shift_mode(mode_id)
    n = int(mode["alert_count"])
    pool = list(_ALERT_BANK)
    random.shuffle(pool)
    # Allow reuse if bank smaller than requested
    while len(pool) < n:
        extra = list(_ALERT_BANK)
        random.shuffle(extra)
        pool.extend(extra)
    selected = pool[:n]
    out = []
    for i, a in enumerate(selected):
        cid = a.get("client_id") or "contoso"
        client = _CLIENT_BY_ID.get(cid) or MSSP_CLIENTS[0]
        sla_min = int(a.get("sla_minutes") or 30)
        out.append({
            "idx": i,
            "title": a["title"],
            "severity": a["severity"],
            "source": a["source"],
            "detail": a["detail"],
            "correct_disposition": a["disposition"],
            "correct_mitre": a.get("mitre") or "",
            "hint": a.get("hint") or "",
            "client_id": client["id"],
            "client_name": client["name"],
            "client_tier": client.get("tier") or "",
            "sla_minutes": sla_min,
            "sla_seconds": sla_min * 60,
        })
    return out


def _hygiene_ok(summary: str, next_action: str, notes: str) -> bool:
    """True when ticket hygiene fields (or composed notes) meet minimum length."""
    s = (summary or "").strip()
    n = (next_action or "").strip()
    if len(s) >= 8 and len(n) >= 8:
        return True
    # Back-compat: older answers used a single notes blob
    return len((notes or "").strip()) >= 12


def score_shift_answers(alerts: list[dict], answers: list[dict]) -> dict[str, Any]:
    """
    Score a completed shift (G2/G3 fields included).

    answers: [{idx, disposition, mitre, notes, client_id, summary, next_action,
               elapsed_sec}]
    """
    by_idx = {a["idx"]: a for a in alerts}
    correct = 0
    graded = []
    for ans in answers:
        idx = int(ans.get("idx", -1))
        alert = by_idx.get(idx)
        if not alert:
            continue
        disp = (ans.get("disposition") or "").strip().lower()
        mitre = (ans.get("mitre") or "").strip().upper()
        notes = (ans.get("notes") or "").strip()
        summary = (ans.get("summary") or "").strip()
        next_action = (ans.get("next_action") or ans.get("next") or "").strip()
        picked_client = (ans.get("client_id") or "").strip().lower()
        elapsed = ans.get("elapsed_sec")
        try:
            elapsed_n = int(elapsed) if elapsed is not None else None
        except (TypeError, ValueError):
            elapsed_n = None

        disp_ok = disp == alert["correct_disposition"]
        need_mitre = bool(alert.get("correct_mitre"))
        correct_m = (alert.get("correct_mitre") or "").strip().upper()
        if need_mitre:
            mitre_ok = bool(mitre) and (
                correct_m == mitre
                or correct_m in mitre
                or mitre in correct_m
            )
        else:
            mitre_ok = not mitre

        hygiene_ok = _hygiene_ok(summary, next_action, notes)
        client_ok = picked_client == (alert.get("client_id") or "").strip().lower()
        sla_seconds = int(alert.get("sla_seconds") or (int(alert.get("sla_minutes") or 30) * 60))
        if elapsed_n is None:
            sla_ok = False
        else:
            sla_ok = elapsed_n <= sla_seconds

        pts = 0
        if disp_ok:
            pts += 2
        if mitre_ok:
            pts += 1
        if hygiene_ok:
            pts += 1
        if client_ok:
            pts += 1
        if sla_ok:
            pts += 1
        max_pts = 6
        if disp_ok:
            correct += 1
        graded.append({
            "idx": idx,
            "title": alert["title"],
            "client_name": alert.get("client_name") or "",
            "disposition": disp,
            "correct_disposition": alert["correct_disposition"],
            "disp_ok": disp_ok,
            "mitre_ok": mitre_ok,
            "notes_ok": hygiene_ok,
            "hygiene_ok": hygiene_ok,
            "client_ok": client_ok,
            "sla_ok": sla_ok,
            "points": pts,
            "max_points": max_pts,
            "hint": alert.get("hint") or "",
            "correct_mitre": alert.get("correct_mitre") or "",
            "correct_client_id": alert.get("client_id") or "",
        })
    total_pts = sum(g["points"] for g in graded)
    max_pts = sum(g["max_points"] for g in graded) or 1
    pct = round(100 * total_pts / max_pts)
    return {
        "correct_dispositions": correct,
        "total_alerts": len(graded),
        "points": total_pts,
        "max_points": max_pts,
        "pct": pct,
        "graded": graded,
    }


def compute_track_stats(counts: dict[str, int]) -> list[dict[str, Any]]:
    """Merge raw activity counts into track progress cards."""
    tracks = []
    for t in SOC_TRACKS:
        raw = int(counts.get(t["id"], 0))
        target = int(t["target"])
        pct = min(100, round(100 * raw / max(target, 1)))
        tracks.append({
            **t,
            "count": raw,
            "pct": pct,
            "status": "ready" if pct >= 100 else ("building" if pct >= 40 else "start"),
        })
    return tracks


def overall_readiness(tracks: list[dict[str, Any]]) -> int:
    """Average track completion 0–100 for hub score."""
    if not tracks:
        return 0
    return round(sum(t["pct"] for t in tracks) / len(tracks))


def alerts_to_json(alerts: list[dict]) -> str:
    """Serialize shift alerts for DB storage."""
    return json.dumps(alerts)


def alerts_from_json(raw: str | None) -> list[dict]:
    """Deserialize shift alerts."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except Exception:
        return []


# Labels for shift-bank technique IDs not (yet) in mitre_reference.py
_SHIFT_MITRE_LABELS: dict[str, dict[str, str]] = {
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "T1021.001": {
        "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement",
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
    },
    "T1114.003": {
        "name": "Email Collection: Email Forwarding Rule",
        "tactic": "Collection",
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactic": "Persistence",
    },
}


def get_shift_mitre_options() -> list[dict[str, str]]:
    """
    Dropdown options for shift MITRE field (Approach A).

    Includes Boundry mitre_reference pack + every ID used in the shift alert
    bank. Wrong picks from the same list act as distractors.
    Always starts with an empty 'N/A' option for FP / no-technique alerts.
    """
    from mitre_reference import TECHNIQUES

    by_id: dict[str, dict[str, str]] = {}

    for tid, meta in TECHNIQUES.items():
        by_id[tid] = {
            "id": tid,
            "name": meta.get("name") or tid,
            "tactic": meta.get("tactic") or "",
            "label": f"{tid} — {meta.get('name') or tid}",
        }

    # Ensure every answer-key ID is present (even if not in Boundry pack yet)
    for alert in _ALERT_BANK:
        tid = (alert.get("mitre") or "").strip()
        if not tid or tid in by_id:
            continue
        extra = _SHIFT_MITRE_LABELS.get(tid, {})
        name = extra.get("name") or tid
        by_id[tid] = {
            "id": tid,
            "name": name,
            "tactic": extra.get("tactic") or "",
            "label": f"{tid} — {name}",
        }

    options = sorted(by_id.values(), key=lambda x: x["id"])
    return [
        {"id": "", "name": "N/A — none / not applicable", "tactic": "", "label": "N/A — none / not applicable"},
        *options,
    ]
