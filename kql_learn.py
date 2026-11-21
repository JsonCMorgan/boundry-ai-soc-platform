"""
KQL Learn Track — teach → practice → quiz for Microsoft Sentinel / Azure Data Explorer.

Maps SPL mental models Jason already knows onto KQL (where, summarize, ago).
Deterministic local grading — no Azure dependency.
"""

from __future__ import annotations

import re
from typing import Any

TRACK_ID = "kql"
TRACK_TITLE = "KQL Learn Track"
TRACK_BLURB = (
    "Sentinel interviews expect KQL. Learn the same analyst moves you know from SPL — "
    "filter, time-scope, aggregate — in Kusto Query Language. Local practice only."
)

# ── Lessons (order matters) ───────────────────────────────────────────────────
LESSONS: list[dict[str, Any]] = [
    {
        "id": "k1_mental_model",
        "order": 1,
        "title": "SPL → KQL mental model",
        "minutes": 8,
        "goal": "Translate Boundry SPL habits into Sentinel KQL shape.",
        "sections": [
            {
                "heading": "Same job, different grammar",
                "body": (
                    "SPL: filters first, then | commands.\n"
                    "KQL: TableName first, then | operators.\n\n"
                    "SPL:  event_type=logon_failed earliest=-1h | stats count by src_ip\n"
                    "KQL:  SigninLogs\n"
                    "      | where TimeGenerated > ago(1h)\n"
                    "      | where ResultType != 0\n"
                    "      | summarize count() by IPAddress\n\n"
                    "Interview tip: say the table name out loud first "
                    "(SigninLogs, SecurityAlert, DeviceProcessEvents)."
                ),
            },
            {
                "heading": "Pipe culture is shared",
                "body": (
                    "Both languages chain with |. Think in stages:\n"
                    "1) pick the table  2) where (filter)  3) summarize / project  4) sort / take"
                ),
            },
        ],
        "key_commands": [
            "SigninLogs",
            "SecurityAlert",
            "| where …",
            "| summarize count() by …",
        ],
        "try_query": "SigninLogs | where TimeGenerated > ago(1h) | take 10",
        "try_why": "Sentinel starter — recent sign-ins, capped for triage.",
    },
    {
        "id": "k2_where_project",
        "order": 2,
        "title": "where + project",
        "minutes": 10,
        "goal": "Filter rows and shape columns for tickets.",
        "sections": [
            {
                "heading": "| where",
                "body": (
                    "Boolean filters after the table:\n\n"
                    "  SigninLogs\n"
                    "  | where ResultType != 0\n"
                    "  | where UserPrincipalName == \"jsmith@contoso.com\"\n\n"
                    "Operators: == != =~ contains has startswith\n"
                    "Combine with and / or (lowercase keywords in KQL)."
                ),
            },
            {
                "heading": "| project",
                "body": (
                    "Pick columns (like SPL | table):\n\n"
                    "  | project TimeGenerated, UserPrincipalName, IPAddress, ResultType\n\n"
                    "Use project early so handoffs stay readable."
                ),
            },
        ],
        "key_commands": [
            "| where ResultType != 0",
            "| where UserPrincipalName == \"…\"",
            "| project TimeGenerated, IPAddress",
            "and / or",
        ],
        "try_query": (
            "SigninLogs | where ResultType != 0 | project TimeGenerated, UserPrincipalName, "
            "IPAddress, ResultType | take 25"
        ),
        "try_why": "Failed/non-success sign-ins as a clean ticket table.",
    },
    {
        "id": "k3_ago_time",
        "order": 3,
        "title": "ago() time windows",
        "minutes": 8,
        "goal": "Scope hunts with ago(1h), ago(1d), ago(7d).",
        "sections": [
            {
                "heading": "TimeGenerated + ago()",
                "body": (
                    "Sentinel rows usually filter on TimeGenerated:\n\n"
                    "  | where TimeGenerated > ago(1h)   // last hour\n"
                    "  | where TimeGenerated > ago(1d)   // last day\n"
                    "  | where TimeGenerated > ago(7d)   // last week\n\n"
                    "SPL earliest=-24h ≈ KQL ago(1d)."
                ),
            },
            {
                "heading": "Shift habit",
                "body": (
                    "Open every hunt with a time bound. Interviewers love: "
                    "'I scoped to ago(1h) first, then widened to ago(1d).'"
                ),
            },
        ],
        "key_commands": [
            "| where TimeGenerated > ago(1h)",
            "| where TimeGenerated > ago(1d)",
            "| where TimeGenerated > ago(7d)",
            "ago(30m)",
        ],
        "try_query": "SigninLogs | where TimeGenerated > ago(1d) | where ResultType != 0 | take 50",
        "try_why": "Failed sign-ins in the last day — spray/brute starting point.",
    },
    {
        "id": "k4_summarize",
        "order": 4,
        "title": "summarize — the money operator",
        "minutes": 12,
        "goal": "Aggregate like SPL stats count by.",
        "sections": [
            {
                "heading": "summarize count() by",
                "body": (
                    "SPL:  | stats count by src_ip | sort -count | head 10\n"
                    "KQL:  | summarize Failures=count() by IPAddress\n"
                    "      | order by Failures desc\n"
                    "      | take 10\n\n"
                    "Also: dcount(), max(), min(), make_set()."
                ),
            },
            {
                "heading": "Interview framing",
                "body": (
                    "Say: 'I summarize failed sign-ins by IPAddress, order descending, "
                    "and investigate the top offenders.' That maps 1:1 to Splunk language."
                ),
            },
        ],
        "key_commands": [
            "| summarize count() by IPAddress",
            "| order by Count desc",
            "| take 10",
            "dcount(UserPrincipalName)",
        ],
        "try_query": (
            "SigninLogs | where TimeGenerated > ago(1d) | where ResultType != 0 "
            "| summarize Failures=count() by IPAddress | order by Failures desc | take 10"
        ),
        "try_why": "Top attacking IPs by failed sign-in volume.",
    },
    {
        "id": "k5_signinlogs",
        "order": 5,
        "title": "SigninLogs hunt patterns",
        "minutes": 10,
        "goal": "Run Tier-1 identity hunts interviewers expect.",
        "sections": [
            {
                "heading": "Fields that matter",
                "body": (
                    "  UserPrincipalName  — account\n"
                    "  IPAddress          — source IP\n"
                    "  ResultType         — 0 = success; non-zero = failure/challenge\n"
                    "  Location / LocationDetails — geo\n"
                    "  AppDisplayName     — app being accessed\n"
                    "  ConditionalAccessStatus — CA outcome"
                ),
            },
            {
                "heading": "Spray vs brute",
                "body": (
                    "Many users, one IP → spray:\n"
                    "  | summarize Users=dcount(UserPrincipalName), Failures=count() by IPAddress\n\n"
                    "One user, many failures → brute:\n"
                    "  | where UserPrincipalName == \"…\" | summarize count() by bin(TimeGenerated, 5m)"
                ),
            },
        ],
        "key_commands": [
            "ResultType != 0",
            "dcount(UserPrincipalName)",
            "AppDisplayName",
            "Location",
        ],
        "try_query": (
            "SigninLogs | where TimeGenerated > ago(1h) | where ResultType != 0 "
            "| summarize Users=dcount(UserPrincipalName), Failures=count() by IPAddress "
            "| where Users > 5 | order by Failures desc"
        ),
        "try_why": "Password-spray smell — one IP hitting many users.",
    },
    {
        "id": "k6_securityalert",
        "order": 6,
        "title": "SecurityAlert + handoff queries",
        "minutes": 10,
        "goal": "Triage Sentinel alerts and paste clean evidence.",
        "sections": [
            {
                "heading": "SecurityAlert table",
                "body": (
                    "  SecurityAlert\n"
                    "  | where TimeGenerated > ago(1d)\n"
                    "  | where AlertSeverity in (\"High\", \"Medium\")\n"
                    "  | project TimeGenerated, AlertName, AlertSeverity, ProviderName, Entities\n"
                    "  | take 25"
                ),
            },
            {
                "heading": "Ticket paste habit",
                "body": (
                    "Always project a small column set before copying into ServiceNow / Portfolio.\n"
                    "Pair with ticket hygiene: Subject / What / Why / Disposition / MITRE / Next."
                ),
            },
        ],
        "key_commands": [
            "SecurityAlert",
            "AlertSeverity",
            "AlertName",
            "| project … | take 25",
        ],
        "try_query": (
            "SecurityAlert | where TimeGenerated > ago(1d) "
            "| where AlertSeverity == \"High\" "
            "| project TimeGenerated, AlertName, AlertSeverity, ProviderName | take 25"
        ),
        "try_why": "High-severity alert skim for shift start.",
    },
]

# ── Practice (per lesson) ─────────────────────────────────────────────────────
PRACTICE: dict[str, list[dict[str, Any]]] = {
    "k1_mental_model": [
        {
            "id": "pk1a",
            "prompt": "Write a KQL query that reads SigninLogs and returns only 10 rows.",
            "hint": "SigninLogs | take 10",
            "accept": [
                "signinlogs | take 10",
                "signinlogs|take 10",
            ],
            "explain": "Table first, then take — KQL's head equivalent.",
        },
        {
            "id": "pk1b",
            "prompt": "Query SecurityAlert and take 20 rows.",
            "hint": "SecurityAlert | take 20",
            "accept": [
                "securityalert | take 20",
            ],
            "explain": "Same shape: table → take.",
        },
    ],
    "k2_where_project": [
        {
            "id": "pk2a",
            "prompt": "From SigninLogs, keep only non-success rows (ResultType != 0), take 25.",
            "hint": "SigninLogs | where ResultType != 0 | take 25",
            "accept": [
                "signinlogs | where resulttype != 0 | take 25",
            ],
            "explain": "where filters before you cap with take.",
        },
        {
            "id": "pk2b",
            "prompt": (
                "SigninLogs → failed sign-ins → project TimeGenerated, UserPrincipalName, "
                "IPAddress → take 15."
            ),
            "hint": "| where ResultType != 0 | project … | take 15",
            "accept": [
                "signinlogs | where resulttype != 0 | project timegenerated, userprincipalname, ipaddress | take 15",
            ],
            "explain": "project shapes the ticket paste; column order can vary in real life — "
                       "here we expect these three names.",
        },
    ],
    "k3_ago_time": [
        {
            "id": "pk3a",
            "prompt": "SigninLogs from the last 1 hour only (TimeGenerated > ago(1h)), take 50.",
            "hint": "| where TimeGenerated > ago(1h)",
            "accept": [
                "signinlogs | where timegenerated > ago(1h) | take 50",
            ],
            "explain": "ago(1h) ≈ SPL earliest=-1h.",
        },
        {
            "id": "pk3b",
            "prompt": "Failed SigninLogs in the last day (ago(1d)), no take needed.",
            "hint": "ago(1d) and ResultType != 0",
            "accept": [
                "signinlogs | where timegenerated > ago(1d) | where resulttype != 0",
                "signinlogs | where resulttype != 0 | where timegenerated > ago(1d)",
            ],
            "explain": "Two where stages; order may swap.",
        },
    ],
    "k4_summarize": [
        {
            "id": "pk4a",
            "prompt": (
                "Last day failed SigninLogs: summarize count by IPAddress, "
                "order highest first, take 10."
            ),
            "hint": "| summarize count() by IPAddress | order by count_ desc | take 10",
            "accept": [
                "signinlogs | where timegenerated > ago(1d) | where resulttype != 0 | summarize count() by ipaddress | order by count_ desc | take 10",
                "signinlogs | where timegenerated > ago(1d) | where resulttype != 0 | summarize failures=count() by ipaddress | order by failures desc | take 10",
                "signinlogs | where resulttype != 0 | where timegenerated > ago(1d) | summarize count() by ipaddress | order by count_ desc | take 10",
                "signinlogs | where resulttype != 0 | where timegenerated > ago(1d) | summarize failures=count() by ipaddress | order by failures desc | take 10",
            ],
            "explain": "summarize + order + take = SPL stats/sort/head.",
        },
    ],
    "k5_signinlogs": [
        {
            "id": "pk5a",
            "prompt": (
                "Last hour failed sign-ins: summarize dcount of users and count of failures "
                "by IPAddress. Keep IPs where Users > 5. Order by Failures desc."
            ),
            "hint": "Users=dcount(UserPrincipalName), Failures=count()",
            "accept": [
                "signinlogs | where timegenerated > ago(1h) | where resulttype != 0 | summarize users=dcount(userprincipalname), failures=count() by ipaddress | where users > 5 | order by failures desc",
                "signinlogs | where resulttype != 0 | where timegenerated > ago(1h) | summarize users=dcount(userprincipalname), failures=count() by ipaddress | where users > 5 | order by failures desc",
            ],
            "explain": "Classic password-spray starter in Sentinel.",
        },
    ],
    "k6_securityalert": [
        {
            "id": "pk6a",
            "prompt": (
                "SecurityAlert last day, High severity only, project TimeGenerated, AlertName, "
                "AlertSeverity, take 25."
            ),
            "hint": "AlertSeverity == \"High\"",
            "accept": [
                'securityalert | where timegenerated > ago(1d) | where alertseverity == "high" | project timegenerated, alertname, alertseverity | take 25',
                "securityalert | where timegenerated > ago(1d) | where alertseverity == 'high' | project timegenerated, alertname, alertseverity | take 25",
                'securityalert | where alertseverity == "high" | where timegenerated > ago(1d) | project timegenerated, alertname, alertseverity | take 25',
            ],
            "explain": "Alert skim query for shift start / handoff.",
        },
    ],
}

# ── Quizzes (per lesson — keyed by lesson id) ─────────────────────────────────
QUIZZES: dict[str, list[dict[str, Any]]] = {
    "k1_mental_model": [
        {
            "id": "kq1a",
            "q": "In KQL, what usually comes first in a query?",
            "choices": {
                "A": "A field=value filter like SPL",
                "B": "The table name (e.g. SigninLogs)",
                "C": "| summarize",
                "D": "ago(1d) alone",
            },
            "answer": "B",
            "explain": "KQL starts with a table (or let/datatable), then pipes.",
        },
        {
            "id": "kq1b",
            "q": "Which shared habit helps both SPL and KQL hunts?",
            "choices": {
                "A": "Skip filters and dump the whole workspace",
                "B": "Chain stages with | (table → filter → aggregate → sort/take)",
                "C": "Never name the table out loud",
                "D": "Use | eval for every field",
            },
            "answer": "B",
            "explain": "Pipe culture is shared — think in stages.",
        },
        {
            "id": "kq1c",
            "q": "SPL `event_type=logon_failed | stats count by src_ip` maps closest to:",
            "choices": {
                "A": "SigninLogs | where ResultType != 0 | summarize count() by IPAddress",
                "B": "SecurityAlert | take 1",
                "C": "| project only, no table",
                "D": "ago(1h) with no table or where",
            },
            "answer": "A",
            "explain": "Table first, where for failures, summarize by IP — same analyst job.",
        },
        {
            "id": "kq1d",
            "q": "Interview tip for opening a Sentinel hunt:",
            "choices": {
                "A": "Start with | order by without a table",
                "B": "Say the table name first (SigninLogs, SecurityAlert, …)",
                "C": "Only use DeviceProcessEvents forever",
                "D": "Avoid pipes entirely",
            },
            "answer": "B",
            "explain": "Naming the table first shows you know the workspace shape.",
        },
    ],
    "k2_where_project": [
        {
            "id": "kq2a",
            "q": "| project in KQL is most like which SPL idea?",
            "choices": {
                "A": "| stats",
                "B": "| table / column pick",
                "C": "| dedup",
                "D": "earliest=",
            },
            "answer": "B",
            "explain": "project selects/renames columns for readable handoffs.",
        },
        {
            "id": "kq2b",
            "q": "Which filters SigninLogs to non-success rows?",
            "choices": {
                "A": "| where ResultType == 0",
                "B": "| where ResultType != 0",
                "C": "| take ResultType",
                "D": "| summarize ResultType",
            },
            "answer": "B",
            "explain": "ResultType != 0 keeps failures / challenges / blocks.",
        },
        {
            "id": "kq2c",
            "q": "How do you combine two where conditions in KQL?",
            "choices": {
                "A": "AND / OR in ALL CAPS only",
                "B": "and / or (lowercase keywords)",
                "C": "&& and || only",
                "D": "Comma-separated field list",
            },
            "answer": "B",
            "explain": "KQL boolean keywords are lowercase and / or.",
        },
        {
            "id": "kq2d",
            "q": "Why project early in a ticket handoff query?",
            "choices": {
                "A": "It encrypts columns",
                "B": "Small column sets stay readable for ServiceNow / peers",
                "C": "summarize refuses wide tables",
                "D": "It replaces TimeGenerated",
            },
            "answer": "B",
            "explain": "Analysts paste clean columns — not every field in the schema.",
        },
    ],
    "k3_ago_time": [
        {
            "id": "kq3a",
            "q": "SPL earliest=-1h is closest to which KQL snippet?",
            "choices": {
                "A": "| where TimeGenerated < ago(1h)",
                "B": "| where TimeGenerated > ago(1h)",
                "C": "| take 1h",
                "D": "| sort ago(1h)",
            },
            "answer": "B",
            "explain": "ago(1h) is one hour before now; greater-than keeps recent rows.",
        },
        {
            "id": "kq3b",
            "q": "Which scopes a hunt to the last day?",
            "choices": {
                "A": "| where TimeGenerated > ago(1d)",
                "B": "| where TimeGenerated > ago(1h)",
                "C": "| take 1d",
                "D": "| project ago(1d)",
            },
            "answer": "A",
            "explain": "ago(1d) ≈ SPL earliest=-24h.",
        },
        {
            "id": "kq3c",
            "q": "Sentinel rows are usually time-scoped on which field?",
            "choices": {
                "A": "EventID",
                "B": "TimeGenerated",
                "C": "AlertSeverity",
                "D": "ProviderName",
            },
            "answer": "B",
            "explain": "TimeGenerated + ago() is the default hunt window habit.",
        },
        {
            "id": "kq3d",
            "q": "Best interview framing for time windows?",
            "choices": {
                "A": "Never bound time; scan forever",
                "B": "Scope tight (ago(1h)) first, then widen (ago(1d))",
                "C": "Only use ago(30d) always",
                "D": "Time filters belong after summarize only",
            },
            "answer": "B",
            "explain": "Start narrow, expand deliberately — shows triage discipline.",
        },
    ],
    "k4_summarize": [
        {
            "id": "kq4a",
            "q": "Which operator aggregates like SPL | stats count by IP?",
            "choices": {
                "A": "| project",
                "B": "| take",
                "C": "| summarize count() by IPAddress",
                "D": "| extend",
            },
            "answer": "C",
            "explain": "summarize is the aggregation workhorse.",
        },
        {
            "id": "kq4b",
            "q": "After summarizing failures by IP, how do you show top offenders?",
            "choices": {
                "A": "| order by Failures desc | take 10",
                "B": "| where Failures == 0",
                "C": "| project only IPAddress",
                "D": "| take before summarize",
            },
            "answer": "A",
            "explain": "order + take mirrors SPL sort -count | head.",
        },
        {
            "id": "kq4c",
            "q": "Which summarize helper counts distinct users?",
            "choices": {
                "A": "count()",
                "B": "dcount(UserPrincipalName)",
                "C": "take(UserPrincipalName)",
                "D": "project(UserPrincipalName)",
            },
            "answer": "B",
            "explain": "dcount() = distinct count — key for spray detection.",
        },
        {
            "id": "kq4d",
            "q": "Interview framing for summarize hunts:",
            "choices": {
                "A": "I dump raw rows and eyeball forever",
                "B": "I summarize failed sign-ins by IP, order desc, investigate top offenders",
                "C": "I never aggregate identity logs",
                "D": "summarize replaces where entirely",
            },
            "answer": "B",
            "explain": "That sentence maps 1:1 to Splunk analyst language.",
        },
    ],
    "k5_signinlogs": [
        {
            "id": "kq5a",
            "q": "ResultType != 0 on SigninLogs typically means:",
            "choices": {
                "A": "Successful interactive sign-in only",
                "B": "Non-success (failure / challenge / block)",
                "C": "MFA was skipped",
                "D": "The row is a SecurityAlert",
            },
            "answer": "B",
            "explain": "0 is success; non-zero covers failures and many challenge paths.",
        },
        {
            "id": "kq5b",
            "q": "Which is the better password-spray smell?",
            "choices": {
                "A": "One user, one failure",
                "B": "One IP, many distinct users failing",
                "C": "Many IPs, one success",
                "D": "Empty SigninLogs",
            },
            "answer": "B",
            "explain": "Spray = breadth across accounts from one source.",
        },
        {
            "id": "kq5c",
            "q": "Which SigninLogs field is the source IP?",
            "choices": {
                "A": "UserPrincipalName",
                "B": "IPAddress",
                "C": "AppDisplayName",
                "D": "ResultType",
            },
            "answer": "B",
            "explain": "IPAddress is the source IP column interviewers expect.",
        },
        {
            "id": "kq5d",
            "q": "One user with many failures over time suggests:",
            "choices": {
                "A": "Password spray across the tenant",
                "B": "Brute / stuffing against that account",
                "C": "Empty SecurityAlert table",
                "D": "Successful CA only",
            },
            "answer": "B",
            "explain": "Spray = many users / one IP; brute = one user / many failures.",
        },
    ],
    "k6_securityalert": [
        {
            "id": "kq6a",
            "q": "SecurityAlert is primarily used to:",
            "choices": {
                "A": "Store firewall pcap dumps",
                "B": "Query Sentinel / defender-style alerts for triage",
                "C": "Replace Entra admin center entirely",
                "D": "Compile Python",
            },
            "answer": "B",
            "explain": "SecurityAlert is the alert triage table in many Sentinel workspaces.",
        },
        {
            "id": "kq6b",
            "q": "Why | take 25 during live triage?",
            "choices": {
                "A": "Required for summarize to work",
                "B": "Caps rows so the portal stays usable",
                "C": "Encrypts the result set",
                "D": "Converts UTC to local time",
            },
            "answer": "B",
            "explain": "Same reason as SPL | head — protect the analyst UI.",
        },
        {
            "id": "kq6c",
            "q": "A solid High-severity skim projects which kind of columns?",
            "choices": {
                "A": "Every Entities blob with no filter",
                "B": "TimeGenerated, AlertName, AlertSeverity, ProviderName",
                "C": "Only raw JSON with no project",
                "D": "SigninLogs ResultType only",
            },
            "answer": "B",
            "explain": "Small projected sets paste cleanly into tickets / handoffs.",
        },
        {
            "id": "kq6d",
            "q": "Ticket paste habit after an alert query:",
            "choices": {
                "A": "Copy the entire workspace schema",
                "B": "Project a small column set; pair with Subject / What / Why / Disposition",
                "C": "Never write a disposition",
                "D": "Skip MITRE and next steps",
            },
            "answer": "B",
            "explain": "Clean evidence + ticket hygiene is the Tier-1 standard.",
        },
    ],
}


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return one KQL lesson by id."""
    for lesson in LESSONS:
        if lesson["id"] == lesson_id:
            return lesson
    return None


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Practice exercises for a lesson."""
    return PRACTICE.get(lesson_id, [])


def get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Quiz questions for one lesson (full objects including answers)."""
    return QUIZZES.get(lesson_id, [])


def lesson_ids() -> list[str]:
    """Ordered lesson ids for progress / prove-it checks."""
    return [lesson["id"] for lesson in LESSONS]


def normalize_kql(q: str) -> str:
    """Normalise a KQL query for answer comparison."""
    s = (q or "").strip().lower()
    s = s.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\s*\|\s*", " | ", s)
    s = re.sub(r"\s*=\s*", "=", s)
    s = re.sub(r"\s*!=\s*", "!=", s)
    s = re.sub(r"\s*>\s*", ">", s)
    s = re.sub(r"\s*<\s*", "<", s)
    # Default summarize count() column name in ADX is count_
    s = s.replace("order by count desc", "order by count_ desc")
    return s


def _pipe_stages(q: str) -> list[str]:
    """Split normalised query into table + pipe stages."""
    parts = [p.strip() for p in normalize_kql(q).split("|")]
    return [p for p in parts if p]


def queries_match(user_query: str, target_query: str) -> bool:
    """
    True if user KQL matches an accepted target.

    Allows reordering of consecutive `| where` stages only; other stages
    must match exactly after normalisation.
    """
    u = _pipe_stages(user_query)
    t = _pipe_stages(target_query)
    if not u or not t or len(u) != len(t):
        return False
    if u[0] != t[0]:
        return False

    def collapse_wheres(stages: list[str]) -> tuple[list[str], list[str]]:
        wheres: list[str] = []
        rest: list[str] = []
        i = 1
        while i < len(stages) and stages[i].startswith("where "):
            wheres.append(stages[i])
            i += 1
        rest = stages[i:]
        return sorted(wheres), rest

    u_w, u_rest = collapse_wheres(u)
    t_w, t_rest = collapse_wheres(t)
    return u_w == t_w and u_rest == t_rest


def check_practice_answer(lesson_id: str, practice_id: str, user_query: str) -> dict[str, Any]:
    """Grade a KQL practice answer against accept patterns (local, deterministic)."""
    items = PRACTICE.get(lesson_id, [])
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}

    user_n = normalize_kql(user_query)
    if not user_n:
        return {
            "ok": True,
            "correct": False,
            "verdict": "wrong",
            "explain": "WRONG — empty query. Type a full KQL statement.",
            "hint": item.get("hint"),
            "example": item["accept"][0],
        }

    matched = any(queries_match(user_query, accept) for accept in item["accept"])
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
            "WRONG — that query does not match this exercise. "
            "Check table name, where clauses, summarize/order/take."
        ),
        "hint": item.get("hint"),
        "example": item["accept"][0],
    }


def grade_quiz(lesson_id: str, answers: dict[str, str]) -> dict[str, Any]:
    """Grade a per-lesson quiz submission {question_id: choice letter}."""
    bank = get_quiz(lesson_id)
    if not bank:
        return {
            "ok": False,
            "error": "Unknown lesson quiz",
            "correct": 0,
            "total": 0,
            "pct": 0,
            "passed": False,
            "graded": [],
        }
    graded = []
    correct_n = 0
    for q in bank:
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
    total = len(bank)
    pct = round(100 * correct_n / total) if total else 0
    return {
        "ok": True,
        "lesson_id": lesson_id,
        "correct": correct_n,
        "total": total,
        "pct": pct,
        "passed": pct >= 70,
        "graded": graded,
    }


def public_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Quiz questions for one lesson without answers (client-safe)."""
    return [
        {"id": q["id"], "q": q["q"], "choices": q["choices"]}
        for q in get_quiz(lesson_id)
    ]
