"""
SPL Learn Track — teach → practice → quiz for Boundry SPL-lite.

Matches what spl_engine.py actually supports so lessons transfer to /siem/query.
Built for GTA SOC hire prep (Splunk-style search language).
"""

from __future__ import annotations

import re
from typing import Any

TRACK_ID = "spl"
TRACK_TITLE = "SPL Learn Track"
TRACK_BLURB = (
    "Learn Boundry SPL-lite the way SOC interviews expect: search, filter, "
    "time windows, stats, and hunt queries — then practice and quiz."
)

# ── Lessons (order matters) ───────────────────────────────────────────────────
LESSONS: list[dict[str, Any]] = [
    {
        "id": "l1_search_basics",
        "order": 1,
        "title": "Search basics",
        "minutes": 8,
        "goal": "Run a search and read results like a Tier-1 analyst.",
        "sections": [
            {
                "heading": "What SPL is",
                "body": (
                    "SPL (Search Processing Language) is how analysts ask a SIEM questions. "
                    "In Boundry we use SPL-lite — a focused subset that maps to your siem_events table. "
                    "Real Splunk interviews use the same mental model: start broad, filter, then pipe commands."
                ),
            },
            {
                "heading": "Anatomy of a query",
                "body": (
                    "Most queries look like:\n\n"
                    "  [filters…] [| command] [| command] …\n\n"
                    "Everything before the first | is the search. Everything after a | transforms results.\n\n"
                    "Example:\n"
                    "  severity=HIGH earliest=-24h | head 20\n\n"
                    "Means: HIGH events from the last day, show only 20 rows."
                ),
            },
            {
                "heading": "Fields only — not English",
                "body": (
                    "Boundry SPL-lite does NOT accept natural language.\n\n"
                    "  ❌ Get me the top 25 events from this IP\n"
                    "  ✅ src_ip=198.51.100.9 | head 25\n\n"
                    "Use field=value filters. For text inside descriptions:\n\n"
                    "  description=powershell   → substring match on description\n"
                    "  severity=CRITICAL        → exact field match\n"
                    "  source=firewall          → only firewall events\n\n"
                    "If it isn’t field=value or a pipe command, the engine will reject it."
                ),
            },
        ],
        "key_commands": [
            "severity=HIGH",
            "source=firewall",
            "event_type=logon_failed",
            "| head 20",
        ],
        "try_query": "severity=CRITICAL | head 10",
        "try_why": "Morning triage starter — newest CRITICAL events first (engine sorts by time in many cases; head caps noise).",
    },
    {
        "id": "l2_fields",
        "order": 2,
        "title": "Field filters SOC uses daily",
        "minutes": 10,
        "goal": "Filter by source, severity, host, user, and IPs.",
        "sections": [
            {
                "heading": "Core fields in Boundry",
                "body": (
                    "These map to columns you will see in interviews too:\n\n"
                    "  source       — windows_event, firewall, flask_app, syslog, …\n"
                    "  event_type   — logon_failed, logon_success, …\n"
                    "  severity     — CRITICAL HIGH MEDIUM LOW INFO\n"
                    "  host         — machine name\n"
                    "  user / user_account — account involved\n"
                    "  src_ip / ip  — source IP (ip is an alias)\n"
                    "  dst_ip       — destination IP\n"
                    "  event_id     — Windows event ID (4625, etc.)"
                ),
            },
            {
                "heading": "Combine filters (AND)",
                "body": (
                    "Space-separated filters are AND:\n\n"
                    "  source=windows_event event_type=logon_failed src_ip=203.0.113.44\n\n"
                    "That is: Windows failed logons from that IP only."
                ),
            },
            {
                "heading": "Aliases you can use",
                "body": (
                    "  user  → user_account\n"
                    "  ip    → src_ip\n"
                    "  time / timestamp → created_at\n\n"
                    "Interview tip: say the real field name out loud even if the product allows aliases."
                ),
            },
        ],
        "key_commands": [
            "source=windows_event event_type=logon_failed",
            "user=admin",
            "ip=10.0.0.5",
            "event_id=4625",
        ],
        "try_query": "source=firewall severity=HIGH | head 25",
        "try_why": "High-severity firewall hits — classic perimeter triage.",
    },
    {
        "id": "l3_time",
        "order": 3,
        "title": "Time windows (earliest)",
        "minutes": 8,
        "goal": "Scope hunts to -1h, -24h, -7d like a real SOC shift.",
        "sections": [
            {
                "heading": "Why time matters",
                "body": (
                    "Without a time bound, you drown in history. Every shift starts with a window:\n"
                    "last hour (active incident), last day (standup), last week (hunt)."
                ),
            },
            {
                "heading": "earliest= modifiers",
                "body": (
                    "Boundry accepts:\n\n"
                    "  earliest=-60m   last 60 minutes\n"
                    "  earliest=-1h    last 1 hour\n"
                    "  earliest=-24h   last day\n"
                    "  earliest=-7d    last week\n"
                    "  earliest=-2w    last 2 weeks\n"
                    "  earliest=@d     since midnight (start of today)\n\n"
                    "Example:\n"
                    "  event_type=logon_failed earliest=-1h"
                ),
            },
            {
                "heading": "Shift habit",
                "body": (
                    "Open every investigation with earliest= so your story has a timeline. "
                    "Interviewers love hearing: 'I scoped to the last hour first, then widened.'"
                ),
            },
        ],
        "key_commands": [
            "earliest=-1h",
            "earliest=-24h",
            "earliest=-7d",
            "earliest=@d",
        ],
        "try_query": "event_type=logon_failed earliest=-24h | head 50",
        "try_why": "Failed logons in the last day — spray/brute force starting point.",
    },
    {
        "id": "l4_stats",
        "order": 4,
        "title": "stats count by — the money command",
        "minutes": 12,
        "goal": "Aggregate to spot sprays, top talkers, and outliers.",
        "sections": [
            {
                "heading": "Why analysts live in stats",
                "body": (
                    "Raw events are a firehose. | stats count by <field> answers: "
                    "'who/what is loudest?' That is how you find password spray (many users, one IP) "
                    "vs brute force (one user, many failures)."
                ),
            },
            {
                "heading": "Syntax",
                "body": (
                    "  … | stats count by src_ip\n"
                    "  … | stats count by user_account\n"
                    "  … | stats count by src_ip, user_account\n\n"
                    "Then usually:\n"
                    "  | sort -count | head 10\n\n"
                    "Full example:\n"
                    "  event_type=logon_failed earliest=-24h\n"
                    "  | stats count by src_ip\n"
                    "  | sort -count\n"
                    "  | head 10"
                ),
            },
            {
                "heading": "Interview framing",
                "body": (
                    "Say: 'I aggregate failed logons by source IP, sort descending, and investigate the top offenders.' "
                    "That sentence alone gets you through many SOC screens."
                ),
            },
        ],
        "key_commands": [
            "| stats count by src_ip",
            "| stats count by user_account",
            "| sort -count",
            "| head 10",
        ],
        "try_query": "event_type=logon_failed earliest=-24h | stats count by src_ip | sort -count | head 10",
        "try_why": "Top attacking IPs by failed logon volume.",
    },
    {
        "id": "l5_shape",
        "order": 5,
        "title": "sort, head, table, dedup",
        "minutes": 10,
        "goal": "Shape results for tickets and handoffs.",
        "sections": [
            {
                "heading": "sort",
                "body": (
                    "  | sort -count        highest first (prefix - means descending)\n"
                    "  | sort created_at    ascending time\n"
                    "  | sort -created_at   newest first"
                ),
            },
            {
                "heading": "head",
                "body": (
                    "  | head 20\n\n"
                    "Caps rows. Always head in live SIEM so you do not freeze the UI."
                ),
            },
            {
                "heading": "table",
                "body": (
                    "Pick columns for a clean ticket paste:\n\n"
                    "  | table host src_ip event_type description created_at"
                ),
            },
            {
                "heading": "dedup",
                "body": (
                    "Keep first row per field value:\n\n"
                    "  | dedup host\n\n"
                    "Useful for 'which hosts appeared?' without duplicates."
                ),
            },
        ],
        "key_commands": [
            "| sort -created_at",
            "| head 25",
            "| table host src_ip description",
            "| dedup host",
        ],
        "try_query": "severity=CRITICAL earliest=-7d | table host event_type description created_at | head 25",
        "try_why": "Clean CRITICAL table for a shift handoff note.",
    },
    {
        "id": "l6_where_hunt",
        "order": 6,
        "title": "where + hunt patterns",
        "minutes": 12,
        "goal": "Tighten results and run interview-ready hunt queries.",
        "sections": [
            {
                "heading": "| where",
                "body": (
                    "Post-filter after transforms:\n\n"
                    "  | where severity=\"HIGH\"\n\n"
                    "Use when you already piped and need an extra constraint. "
                    "For simple cases, prefer field=value in the search clause."
                ),
            },
            {
                "heading": "Hunt patterns to memorize",
                "body": (
                    "1) Brute force / spray starters:\n"
                    "  event_type=logon_failed earliest=-1h | stats count by src_ip | sort -count | head 10\n\n"
                    "2) Firewall top talkers:\n"
                    "  source=firewall earliest=-24h | stats count by src_ip | sort -count | head 20\n\n"
                    "3) Admin activity:\n"
                    "  user=admin earliest=-24h | sort -created_at | head 25\n\n"
                    "4) Service installs (persistence smell):\n"
                    "  event_type=service_installed | table host user_account description created_at"
                ),
            },
            {
                "heading": "What Boundry does NOT support (yet)",
                "body": (
                    "Do not expect | eval, | lookup, or | regex in SPL-lite. "
                    "If an interview asks for those, say: 'I'd use eval/lookup in full Splunk; "
                    "in our lab we stay on search, stats, sort, head, table, dedup, where.'"
                ),
            },
        ],
        "key_commands": [
            '| where severity="HIGH"',
            "event_type=logon_failed | stats count by src_ip",
            "source=firewall | stats count by src_ip | sort -count",
            "user=admin | sort -created_at | head 25",
        ],
        "try_query": "source=firewall earliest=-24h | stats count by src_ip | sort -count | head 20",
        "try_why": "Top blocked IPs — perimeter hunt staple.",
    },
]

# ── Practice exercises (per lesson) ───────────────────────────────────────────
# accept: list of normalised-acceptable query strings
# breakdown: plain-English checklist shown in the UI (what the question wants)
PRACTICE: dict[str, list[dict[str, Any]]] = {
    "l1_search_basics": [
        {
            "id": "p1a",
            "prompt": "Show only HIGH severity events, and stop after 20 rows.",
            "breakdown": {
                "goal": "A short HIGH-severity list for triage.",
                "find": "Events where severity is HIGH",
                "time": "Not needed for this one",
                "then": "Limit the results to 20 rows",
            },
            "hint": "severity=… then | head …",
            "accept": [
                "severity=high | head 20",
                "severity=HIGH | head 20",
            ],
            "explain": "Filter severity first, then cap with head so the UI stays fast.",
        },
        {
            "id": "p1b",
            "prompt": "Show only CRITICAL events (any time range), first 10 rows.",
            "breakdown": {
                "goal": "Morning CRITICAL skim — newest noise capped.",
                "find": "Events where severity is CRITICAL",
                "time": "Not needed (any time is fine)",
                "then": "Limit to the first 10 rows",
            },
            "hint": "severity=CRITICAL | head 10",
            "accept": [
                "severity=critical | head 10",
                "severity=CRITICAL | head 10",
            ],
            "explain": "Same pattern as morning triage.",
        },
    ],
    "l2_fields": [
        {
            "id": "p2a",
            "prompt": "Show failed Windows logons only. Use both source and event_type. Limit 25 rows.",
            "breakdown": {
                "goal": "Failed domain/local logons from the Windows source.",
                "find": "source = windows_event AND event_type = logon_failed",
                "time": "Not needed",
                "then": "Limit to 25 rows",
            },
            "hint": "source=windows_event event_type=logon_failed",
            "accept": [
                "source=windows_event event_type=logon_failed | head 25",
                "event_type=logon_failed source=windows_event | head 25",
            ],
            "explain": "Two field filters AND together; order of filters does not matter.",
        },
        {
            "id": "p2b",
            "prompt": "Show firewall events from source IP 198.51.100.9. Cap at 15 rows. (ip= or src_ip= both OK)",
            "breakdown": {
                "goal": "Firewall traffic involving one specific source IP.",
                "find": "source = firewall AND src_ip/ip = 198.51.100.9",
                "time": "Not needed",
                "then": "Limit to 15 rows",
            },
            "hint": "source=firewall ip=…",
            "accept": [
                "source=firewall ip=198.51.100.9 | head 15",
                "source=firewall src_ip=198.51.100.9 | head 15",
                "ip=198.51.100.9 source=firewall | head 15",
                "src_ip=198.51.100.9 source=firewall | head 15",
            ],
            "explain": "ip is an alias for src_ip in Boundry SPL-lite.",
        },
    ],
    "l3_time": [
        {
            "id": "p3a",
            "prompt": "Show failed logons, but only from the last 1 hour.",
            "breakdown": {
                "goal": "Active spray/brute window — last hour only.",
                "find": "event_type = logon_failed",
                "time": "Last 1 hour (earliest=-1h)",
                "then": "No extra pipes required",
            },
            "hint": "event_type=logon_failed earliest=-1h",
            "accept": [
                "event_type=logon_failed earliest=-1h",
                "earliest=-1h event_type=logon_failed",
            ],
            "explain": "Always scope active incidents to a short window first.",
        },
        {
            "id": "p3b",
            "prompt": "Show all CRITICAL events since midnight (start of today).",
            "breakdown": {
                "goal": "Today's CRITICAL pile for standup.",
                "find": "severity = CRITICAL",
                "time": "Since start of today (earliest=@d)",
                "then": "No extra pipes required",
            },
            "hint": "earliest=@d",
            "accept": [
                "severity=critical earliest=@d",
                "severity=CRITICAL earliest=@d",
                "earliest=@d severity=CRITICAL",
                "earliest=@d severity=critical",
            ],
            "explain": "@d = start of today — great for daily standup queries.",
        },
    ],
    "l4_stats": [
        {
            "id": "p4a",
            "prompt": "In the last 24 hours, which source IPs have the most failed logons? Show the top 10.",
            "breakdown": {
                "goal": "Classic password-spray / brute-force starter.",
                "find": "event_type = logon_failed",
                "time": "Last 24 hours (earliest=-24h)",
                "then": "Count by src_ip -> sort highest first -> keep top 10",
            },
            "hint": "stats count by src_ip | sort -count | head 10",
            "accept": [
                "event_type=logon_failed earliest=-24h | stats count by src_ip | sort -count | head 10",
                "earliest=-24h event_type=logon_failed | stats count by src_ip | sort -count | head 10",
                "event_type=logon_failed earliest=-24h | stats count by ip | sort -count | head 10",
            ],
            "explain": "This is the classic spray/brute force starter query.",
        },
        {
            "id": "p4b",
            "prompt": "Over the last 7 days, count successful logons per user. Sort so the busiest users are first. (No head needed.)",
            "breakdown": {
                "goal": "Who is logging in most — spot noisy/unexpected accounts.",
                "find": "event_type = logon_success",
                "time": "Last 7 days (earliest=-7d)",
                "then": "Count by user/user_account -> sort highest count first",
            },
            "hint": "event_type=logon_success … | stats count by user_account | sort -count",
            "accept": [
                "event_type=logon_success earliest=-7d | stats count by user_account | sort -count",
                "earliest=-7d event_type=logon_success | stats count by user_account | sort -count",
                "event_type=logon_success earliest=-7d | stats count by user | sort -count",
            ],
            "explain": "Spot noisy or unexpected accounts.",
        },
    ],
    "l5_shape": [
        {
            "id": "p5a",
            "prompt": "CRITICAL events from the last 7 days. Show only columns: host, event_type, description, created_at. Max 25 rows.",
            "breakdown": {
                "goal": "Ticket-friendly CRITICAL table for the last week.",
                "find": "severity = CRITICAL",
                "time": "Last 7 days (earliest=-7d)",
                "then": "Pick those 4 columns with table -> limit to 25 rows",
            },
            "hint": "| table … | head 25",
            "accept": [
                "severity=critical earliest=-7d | table host event_type description created_at | head 25",
                "severity=CRITICAL earliest=-7d | table host event_type description created_at | head 25",
                "earliest=-7d severity=CRITICAL | table host event_type description created_at | head 25",
            ],
            "explain": "table picks ticket-friendly columns; head protects the UI.",
        },
        {
            "id": "p5b",
            "prompt": "In the last 7 days, list each host only once (dedup). Show host and src_ip.",
            "breakdown": {
                "goal": "Unique hosts seen recently (one row per host).",
                "find": "All events (no severity/source filter)",
                "time": "Last 7 days (earliest=-7d)",
                "then": "dedup host -> table with host + src_ip",
            },
            "hint": "earliest=-7d | dedup host | table …",
            "accept": [
                "earliest=-7d | dedup host | table host src_ip",
                "earliest=-7d | dedup host | table host ip",
            ],
            "explain": "dedup keeps one row per host.",
        },
    ],
    "l6_where_hunt": [
        {
            "id": "p6a",
            "prompt": "Firewall events in the last day. Which source IPs appear most? Top 20.",
            "breakdown": {
                "goal": "Perimeter top-talkers hunt.",
                "find": "source = firewall",
                "time": "Last 24 hours (earliest=-24h)",
                "then": "Count by src_ip -> sort highest first -> top 20",
            },
            "hint": "source=firewall earliest=-24h | stats …",
            "accept": [
                "source=firewall earliest=-24h | stats count by src_ip | sort -count | head 20",
                "earliest=-24h source=firewall | stats count by src_ip | sort -count | head 20",
                "source=firewall earliest=-24h | stats count by ip | sort -count | head 20",
            ],
            "explain": "Perimeter top-talkers hunt.",
        },
        {
            "id": "p6b",
            "prompt": "Show activity for the admin account in the last day. Newest first. Limit 25. Use user=admin.",
            "breakdown": {
                "goal": "Privileged-account monitoring (interview favourite).",
                "find": "user = admin (user_account=admin also OK)",
                "time": "Last 24 hours (earliest=-24h)",
                "then": "Sort newest first (created_at) -> limit 25 rows",
            },
            "hint": "user=admin earliest=-24h | sort -created_at | head 25",
            "accept": [
                "user=admin earliest=-24h | sort -created_at | head 25",
                "earliest=-24h user=admin | sort -created_at | head 25",
                "user_account=admin earliest=-24h | sort -created_at | head 25",
            ],
            "explain": "Privileged account monitoring — interview favourite.",
        },
    ],
}

# ── Quiz (multiple choice) ────────────────────────────────────────────────────
QUIZ: list[dict[str, Any]] = [
    {
        "id": "q1",
        "q": "What does the pipe | mean in SPL?",
        "choices": {
            "A": "Logical OR between filters",
            "B": "Pass results into the next command",
            "C": "Comment out the rest of the line",
            "D": "Join two indexes",
        },
        "answer": "B",
        "explain": "Pipes chain transforming commands: search | stats | sort | head.",
    },
    {
        "id": "q2",
        "q": "Which query best starts a password-spray investigation?",
        "choices": {
            "A": "severity=INFO | head 1000",
            "B": "event_type=logon_failed earliest=-1h | stats count by src_ip | sort -count | head 10",
            "C": "| eval user=upper(user)",
            "D": "dedup only",
        },
        "answer": "B",
        "explain": "Aggregate failed logons by source IP in a short window.",
    },
    {
        "id": "q3",
        "q": "In Boundry SPL-lite, ip= is an alias for which field?",
        "choices": {"A": "dst_ip", "B": "host", "C": "src_ip", "D": "event_id"},
        "answer": "C",
        "explain": "ip → src_ip; user → user_account.",
    },
    {
        "id": "q4",
        "q": "What does earliest=-24h mean?",
        "choices": {
            "A": "Only events older than 24 hours",
            "B": "Events from the last 24 hours",
            "C": "Sample 24 random hours",
            "D": "Sort by hour descending",
        },
        "answer": "B",
        "explain": "Time window: now minus 24 hours through now.",
    },
    {
        "id": "q5",
        "q": "Which command aggregates counts per field value?",
        "choices": {"A": "| table", "B": "| head", "C": "| stats count by …", "D": "| dedup"},
        "answer": "C",
        "explain": "stats count by is the core SOC aggregation.",
    },
    {
        "id": "q6",
        "q": "sort -count means:",
        "choices": {
            "A": "Remove the count column",
            "B": "Ascending by count",
            "C": "Descending by count (highest first)",
            "D": "Sort alphabetically",
        },
        "answer": "C",
        "explain": "Leading - = descending in SPL-lite sort.",
    },
    {
        "id": "q7",
        "q": "Why use | head 20 in live SIEM work?",
        "choices": {
            "A": "It encrypts results",
            "B": "It caps rows so the UI/query stays responsive",
            "C": "It is required for stats",
            "D": "It converts times to UTC",
        },
        "answer": "B",
        "explain": "Always limit during triage; widen later if needed.",
    },
    {
        "id": "q8",
        "q": "earliest=@d means:",
        "choices": {
            "A": "Last 24 hours",
            "B": "Start of today (midnight)",
            "C": "All data forever",
            "D": "Only December",
        },
        "answer": "B",
        "explain": "@d = beginning of current day.",
    },
    {
        "id": "q9",
        "q": "Which is NOT supported in Boundry SPL-lite?",
        "choices": {"A": "| stats count by src_ip", "B": "| eval …", "C": "| table host", "D": "| where severity=\"HIGH\""},
        "answer": "B",
        "explain": "eval/lookup/regex are out of scope; know that for interviews.",
    },
    {
        "id": "q10",
        "q": "Best next step after seeing one IP with hundreds of failures across many users?",
        "choices": {
            "A": "Ignore — probably a scanner FP",
            "B": "Treat as likely password spray: block/investigate src_ip, check for successes",
            "C": "Only reset every password in the company immediately with no ticket",
            "D": "Delete the SIEM index",
        },
        "answer": "B",
        "explain": "Spray pattern → contain source, hunt 4624 successes, document.",
    },
]


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return one lesson by id."""
    for lesson in LESSONS:
        if lesson["id"] == lesson_id:
            return lesson
    return None


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Practice exercises for a lesson (prompts only for clients)."""
    return PRACTICE.get(lesson_id, [])


def normalize_spl(q: str) -> str:
    """Normalise a query for answer comparison."""
    s = (q or "").strip().lower()
    s = s.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\s*\|\s*", " | ", s)
    s = re.sub(r"\s*=\s*", "=", s)
    # drop optional leading 'search'
    if s.startswith("search "):
        s = s[7:].strip()
    return s


def queries_match(user_query: str, target_query: str) -> bool:
    """
    True if user_query is equivalent to target_query.
    Filters before the first pipe may be reordered; pipe stages must match exactly.
    """
    user_n = normalize_spl(user_query)
    target_n = normalize_spl(target_query)
    if not user_n or not target_n:
        return False
    if user_n == target_n:
        return True
    u_parts = [p.strip() for p in user_n.split("|")]
    a_parts = [p.strip() for p in target_n.split("|")]
    if len(u_parts) != len(a_parts):
        return False
    # Token-set compare search clause only (order-insensitive filters)
    if set(u_parts[0].split()) != set(a_parts[0].split()):
        return False
    return u_parts[1:] == a_parts[1:]


def check_practice_answer(lesson_id: str, practice_id: str, user_query: str) -> dict[str, Any]:
    """
    Check a practice answer.
    Search-clause field filters may appear in any order; pipe commands must match.
    Wrong answers return correct=False with hint + example — never a soft pass.
    """
    items = PRACTICE.get(lesson_id, [])
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}

    user_n = normalize_spl(user_query)
    if not user_n:
        return {
            "ok": True,
            "correct": False,
            "verdict": "wrong",
            "explain": "WRONG — empty query. Type a full SPL-lite statement.",
            "hint": item.get("hint"),
            "example": item["accept"][0],
        }

    matched = any(queries_match(user_query, accept) for accept in item["accept"])

    # Also verify it parses in SPL-lite when marked correct
    parse_error = None
    if matched:
        try:
            import spl_engine
            # Parse normalised form so "severity = HIGH" still counts once matched
            parsed = spl_engine.parse_spl(normalize_spl(user_query), ph="?")
            if parsed.get("error"):
                matched = False
                parse_error = parsed["error"]
        except Exception as exc:
            matched = False
            parse_error = str(exc)

    if matched:
        return {
            "ok": True,
            "correct": True,
            "verdict": "correct",
            "explain": item["explain"],
            "hint": None,
            "example": None,
        }

    return {
        "ok": True,
        "correct": False,
        "verdict": "wrong",
        "explain": (
            f"WRONG — {parse_error}"
            if parse_error
            else "WRONG — that query does not match this exercise. "
                 "Check field names, values, pipes, and head/stats."
        ),
        "hint": item.get("hint"),
        "example": item["accept"][0],
    }


def grade_quiz(answers: dict[str, str]) -> dict[str, Any]:
    """Grade quiz submission {question_id: choice letter}."""
    graded = []
    correct_n = 0
    for q in QUIZ:
        picked = (answers.get(q["id"]) or "").strip().upper()
        ok = picked == q["answer"]
        if ok:
            correct_n += 1
        graded.append({
            "id": q["id"],
            "correct": ok,
            "picked": picked,
            "answer": q["answer"],
            "explain": q["explain"],
            "q": q["q"],
        })
    total = len(QUIZ)
    pct = round(100 * correct_n / total) if total else 0
    return {
        "correct": correct_n,
        "total": total,
        "pct": pct,
        "passed": pct >= 70,
        "graded": graded,
    }


def public_quiz() -> list[dict[str, Any]]:
    """Quiz questions without answers for the client."""
    return [
        {"id": q["id"], "q": q["q"], "choices": q["choices"]}
        for q in QUIZ
    ]


# ── Sample SIEM pack (Option A) ─────────────────────────────────────────────
# Tagged training events so every lesson try_query / practice pattern returns rows.
# Identified by event_id prefix SPLLEARN- and "[SPL Learn]" in description.

SAMPLE_PACK_TAG = "[SPL Learn]"
SAMPLE_EVENT_PREFIX = "SPLLEARN-"

# (source, event_id_suffix, event_type, severity, host, user, src_ip, dst_ip, description)
_SAMPLE_EVENTS: list[tuple] = [
    # CRITICAL — L1 / L5 try_query
    ("windows_event", "CRIT-01", "logon_failed", "CRITICAL", "DC01", "admin",
     "203.0.113.50", "", "CRITICAL: repeated admin lockouts from external IP"),
    ("windows_event", "CRIT-02", "account_created", "CRITICAL", "DC01", "attacker",
     "203.0.113.50", "", "CRITICAL: unexpected local admin account created overnight"),
    ("endpoint", "CRIT-03", "process_created", "CRITICAL", "WS-HR-03", "jsmith",
     "10.0.10.44", "", "CRITICAL: excel.exe spawned encoded PowerShell"),
    ("identity", "CRIT-04", "mailbox_rule", "CRITICAL", "MAIL01", "cfo",
     "198.51.100.20", "", "CRITICAL: inbox forward rule to external Gmail"),
    ("windows_event", "CRIT-05", "special_privilege_logon", "CRITICAL", "DC01", "svc_backup2",
     "10.0.10.8", "", "CRITICAL: special privileges assigned to unused service account"),

    # Firewall HIGH + volume for stats — L2 / L6
    ("firewall", "FW-01", "firewall_block", "HIGH", "edge-fw", "",
     "198.51.100.9", "10.0.10.5", "DROP tcp/445 from 198.51.100.9 (SMB probe)"),
    ("firewall", "FW-02", "firewall_block", "HIGH", "edge-fw", "",
     "198.51.100.9", "10.0.10.5", "DROP tcp/445 repeat from 198.51.100.9"),
    ("firewall", "FW-03", "firewall_block", "HIGH", "edge-fw", "",
     "198.51.100.9", "10.0.10.12", "DROP tcp/445 to fileserver"),
    ("firewall", "FW-04", "firewall_block", "HIGH", "edge-fw", "",
     "203.0.113.88", "10.0.10.2", "DROP tcp/3389 RDP from internet"),
    ("firewall", "FW-05", "firewall_block", "HIGH", "edge-fw", "",
     "203.0.113.88", "10.0.10.2", "DROP tcp/3389 repeat"),
    ("firewall", "FW-06", "firewall_block", "MEDIUM", "edge-fw", "",
     "192.0.2.15", "10.0.10.20", "DROP tcp/22 SSH scan"),
    ("firewall", "FW-07", "firewall_block", "MEDIUM", "edge-fw", "",
     "192.0.2.15", "10.0.10.21", "DROP tcp/22 SSH scan host2"),
    ("firewall", "FW-08", "firewall_block", "HIGH", "edge-fw", "",
     "198.51.100.40", "10.0.10.5", "DROP tcp/445 lateral probe"),

    # Failed logons — multiple IPs for stats (L3/L4) + windows_event practice
    ("windows_event", "4625-A1", "logon_failed", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "4625 failed logon jsmith (brute force burst)"),
    ("windows_event", "4625-A2", "logon_failed", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "4625 failed logon jsmith attempt 2"),
    ("windows_event", "4625-A3", "logon_failed", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "4625 failed logon jsmith attempt 3"),
    ("windows_event", "4625-A4", "logon_failed", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "4625 failed logon jsmith attempt 4"),
    ("windows_event", "4625-A5", "logon_failed", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "4625 failed logon jsmith attempt 5"),
    ("windows_event", "4625-B1", "logon_failed", "HIGH", "DC01", "alice",
     "203.0.113.77", "", "4625 spray hit alice"),
    ("windows_event", "4625-B2", "logon_failed", "HIGH", "DC01", "bob",
     "203.0.113.77", "", "4625 spray hit bob"),
    ("windows_event", "4625-B3", "logon_failed", "HIGH", "DC01", "carol",
     "203.0.113.77", "", "4625 spray hit carol"),
    ("windows_event", "4625-B4", "logon_failed", "HIGH", "DC01", "dave",
     "203.0.113.77", "", "4625 spray hit dave"),
    ("windows_event", "4625-C1", "logon_failed", "MEDIUM", "WS-FIN-12", "eve",
     "10.0.10.99", "", "4625 local failed logon eve"),
    ("windows_event", "4625-C2", "logon_failed", "MEDIUM", "WS-FIN-12", "eve",
     "10.0.10.99", "", "4625 local failed logon eve 2"),

    # Specific IP used in practice p2b
    ("firewall", "FW-P2B", "firewall_block", "HIGH", "edge-fw", "",
     "198.51.100.9", "10.0.10.5", "DROP involving 198.51.100.9 for SPL practice"),

    # Success logons for L4 practice (by user)
    ("windows_event", "4624-1", "logon_success", "INFO", "DC01", "alice",
     "10.0.10.30", "", "4624 successful logon alice"),
    ("windows_event", "4624-2", "logon_success", "INFO", "DC01", "alice",
     "10.0.10.30", "", "4624 successful logon alice 2"),
    ("windows_event", "4624-3", "logon_success", "INFO", "DC01", "bob",
     "10.0.10.31", "", "4624 successful logon bob"),
    ("windows_event", "4624-4", "logon_success", "INFO", "DC01", "admin",
     "10.0.10.2", "", "4624 successful logon admin"),
    ("windows_event", "4624-5", "logon_success", "INFO", "DC01", "admin",
     "10.0.10.2", "", "4624 successful logon admin 2"),
    ("windows_event", "4624-6", "logon_success", "INFO", "DC01", "admin",
     "10.0.10.2", "", "4624 successful logon admin 3"),

    # Admin activity — L6 practice user=admin
    ("windows_event", "ADM-1", "explicit_cred_logon", "MEDIUM", "DC01", "admin",
     "10.0.10.2", "", "admin explicit credential logon"),
    ("windows_event", "ADM-2", "group_member_added", "HIGH", "DC01", "admin",
     "10.0.10.2", "", "admin added user to Domain Admins"),

    # Service install hunt pattern from lessons
    ("windows_event", "SVC-1", "service_installed", "MEDIUM", "WS-HR-03", "SYSTEM",
     "10.0.10.44", "", "New service installed (persistence smell)"),
    ("windows_event", "SVC-2", "service_installed", "HIGH", "WS-HR-03", "SYSTEM",
     "10.0.10.44", "", "Suspicious service binary path under Temp"),

    # Extra HIGH for severity filters
    ("windows_event", "HIGH-1", "account_locked_out", "HIGH", "DC01", "jsmith",
     "203.0.113.44", "", "Account lockout after failed logons"),
    ("syslog", "HIGH-2", "ids_alert", "HIGH", "ids-01", "",
     "203.0.113.88", "10.0.10.2", "IDS signature: RDP brute force"),
]


def sample_pack_events() -> list[dict[str, Any]]:
    """Return ingest-ready dicts for the SPL Learn sample pack."""
    out = []
    for source, suffix, etype, sev, host, user, src, dst, desc in _SAMPLE_EVENTS:
        out.append({
            "source": source,
            "event_id": f"{SAMPLE_EVENT_PREFIX}{suffix}",
            "event_type": etype,
            "severity": sev,
            "host": host,
            "user": user,
            "src_ip": src,
            "dst_ip": dst,
            "description": f"{SAMPLE_PACK_TAG} {desc}",
            "raw": {"pack": "spl_learn", "training": True},
            "simulated": 1,
        })
    return out
