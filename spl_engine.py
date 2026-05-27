"""
SPL-lite Engine — Boundry.AI SIEM
Translates a subset of Splunk Processing Language to SQLite queries
against the siem_events table.

Supported syntax:
  [search] [field=value ...] [earliest=-Nh|-Nd|-Nw] [keyword ...]
  | stats count by <field>[, <field>]
  | sort [-]<field>[, [-]<field>]
  | head <N>
  | table <field> [<field> ...]
  | dedup <field>
  | where <field>="<value>"
  | rex field=<field> "<named_group_regex>"   (extract to virtual col — not in v1)
"""

import re
from typing import Any

# Cap distinct groups returned by | stats count by to avoid high-cardinality blowups.
MAX_STATS_GROUPS = 500

# ---------------------------------------------------------------------------
# Column allow-list (prevents arbitrary column injection)
# ---------------------------------------------------------------------------
_ALLOWED_COLS = {
    "id", "source", "event_id", "event_type", "severity", "host",
    "user_account", "src_ip", "dst_ip", "description", "raw", "created_at",
    # aggregation alias
    "count",
    # user-friendly aliases mapped below
    "user", "timestamp", "ip",
}

_COL_ALIASES = {
    "user": "user_account",
    "timestamp": "created_at",
    "ip": "src_ip",
    "time": "created_at",
}

_SAFE_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_SAFE_SOURCES = {
    "windows_event", "firewall", "flask_app", "syslog",
    "siem_rule", "scheduled_task", "service_install",
}


def _safe_col(col: str) -> str:
    """Validate and normalise a column name. Raises ValueError on unknown cols."""
    c = col.strip().lower()
    c = _COL_ALIASES.get(c, c)
    if c not in _ALLOWED_COLS:
        raise ValueError(f"Unknown column '{col}'. Allowed: {', '.join(sorted(_ALLOWED_COLS - {'count'}))}")
    return c


# ---------------------------------------------------------------------------
# Tokeniser: handles quoted strings and field=value tokens
# ---------------------------------------------------------------------------
_TOKEN_RE = re.compile(
    r'(?:[^\s"\'|=]+=["\'][^"\']*["\'])'   # field="quoted value"
    r'|(?:[^\s"\'|=]+=[^\s"\'|]+)'         # field=bare_value
    r'|(?:"[^"]*")'                         # "quoted keyword"
    r"|(?:'[^']*')"                         # 'quoted keyword'
    r'|(?:[^\s|]+)'                         # bare word
)


def _split_pipes(query: str) -> list[str]:
    """Split on | not inside quotes."""
    parts: list[str] = []
    current: list[str] = []
    in_q: str | None = None
    for ch in query:
        if ch in ('"', "'") and in_q is None:
            in_q = ch
            current.append(ch)
        elif ch == in_q:
            in_q = None
            current.append(ch)
        elif ch == "|" and in_q is None:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _parse_time_offset(val: str) -> str:
    """
    Convert SPL time modifier to SQLite datetime expression.
    Accepts: -1h, -24h, -7d, -30d, -2w, -60m
    Also accepts bare integers as seconds offset.
    """
    val = val.strip()
    # absolute datetime passthrough (not supported in v1)
    m = re.match(r"^-(\d+)(m|h|d|w)$", val, re.IGNORECASE)
    if m:
        n, unit = int(m.group(1)), m.group(2).lower()
        if unit == "w":
            return f"datetime('now', '-{n * 7} days')"
        unit_map = {"m": "minutes", "h": "hours", "d": "days"}
        return f"datetime('now', '-{n} {unit_map[unit]}')"
    # "@d" means start of today
    if val.lower() == "@d":
        return "date('now')"
    if val.lower() == "now":
        return "datetime('now')"
    raise ValueError(
        f"Invalid time value '{val}'. Use formats like: -1h  -24h  -7d  -30d  -2w  -60m  @d"
    )


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_spl(query: str, ph: str = "?") -> dict[str, Any]:
    """
    Parse an SPL-lite query string and return::

        {
            "sql":         "SELECT ... FROM siem_events ...",
            "params":      [...],          # positional params for db_fetchall
            "columns":     ["col1", ...],  # display column names in order
            "explanation": "Human-readable summary",
            "error":       None | "message if parse failed",
        }

    ``ph`` is the SQL placeholder character — "?" for SQLite, "%s" for PostgreSQL.
    """
    result: dict[str, Any] = {
        "sql": "", "params": [], "columns": [],
        "explanation": "", "error": None,
    }

    query = query.strip()
    if not query:
        result["error"] = "Empty query"
        return result

    try:
        parsed = _do_parse(query, ph)
        result.update(parsed)
    except ValueError as exc:
        result["error"] = str(exc)

    return result


def _do_parse(query: str, ph: str) -> dict[str, Any]:
    parts = _split_pipes(query)
    search_str = parts[0]
    commands = parts[1:]

    # ── Parse the search part ────────────────────────────────────────────────
    where_clauses: list[str] = []
    params: list[Any] = []
    keywords: list[str] = []

    tokens = _TOKEN_RE.findall(search_str)
    for tok in tokens:
        lower = tok.lower()
        if lower in ("search", "index=main", "index=*", "*"):
            continue  # ignore leading 'search' keyword

        if "=" in tok and not tok.startswith('"') and not tok.startswith("'"):
            field, _, raw_val = tok.partition("=")
            field = field.strip().lower()
            val = raw_val.strip().strip('"').strip("'")

            if field == "earliest":
                expr = _parse_time_offset(val)
                where_clauses.append(f"created_at >= {expr}")
            elif field == "latest":
                expr = _parse_time_offset(val)
                where_clauses.append(f"created_at <= {expr}")
            elif field == "severity":
                sv = val.upper()
                if sv not in _SAFE_SEVERITIES:
                    raise ValueError(f"severity must be one of: {', '.join(_SAFE_SEVERITIES)}")
                where_clauses.append(f"severity = {ph}")
                params.append(sv)
            elif field in ("source", "src_ip", "dst_ip", "host", "event_type", "event_id"):
                where_clauses.append(f"{field} = {ph}")
                params.append(val)
            elif field in ("user", "user_account"):
                where_clauses.append(f"user_account = {ph}")
                params.append(val)
            elif field == "description":
                where_clauses.append(f"description LIKE {ph}")
                params.append(f"%{val}%")
            else:
                raise ValueError(
                    f"Unknown filter field '{field}'. "
                    f"Supported: source, severity, src_ip, dst_ip, host, user, "
                    f"event_type, event_id, description, earliest, latest"
                )
        else:
            # bare keyword — strip surrounding quotes
            kw = tok.strip().strip('"').strip("'")
            if kw:
                keywords.append(kw)

    # Full-text keyword search
    if keywords:
        for kw in keywords:
            pat = f"%{kw}%"
            where_clauses.append(
                f"(description LIKE {ph} OR event_type LIKE {ph} "
                f"OR host LIKE {ph} OR src_ip LIKE {ph} OR user_account LIKE {ph})"
            )
            params.extend([pat, pat, pat, pat, pat])

    # ── Parse pipe commands ──────────────────────────────────────────────────
    # Default column set for raw event queries
    select_parts: list[str] = [
        "id", "created_at", "severity", "source",
        "event_type", "host", "user_account", "src_ip", "dst_ip", "description",
    ]
    group_by: list[str] = []
    order_by: list[str] = []
    limit_n: int = 100
    has_stats = False
    dedup_col: str | None = None
    _extra_where: list[str] = []
    _extra_params: list[Any] = []

    for cmd_str in commands:
        cmd_str = cmd_str.strip()
        if not cmd_str:
            continue
        cmd_tokens = cmd_str.split(None, 1)
        cmd = cmd_tokens[0].lower()
        args = cmd_tokens[1].strip() if len(cmd_tokens) > 1 else ""

        # ---- stats count by ------------------------------------------------
        if cmd == "stats":
            m = re.match(r"count\s+by\s+(.+)$", args, re.IGNORECASE)
            if not m:
                raise ValueError(
                    "Usage: | stats count by <field>[, <field>]\n"
                    "Example: | stats count by src_ip"
                )
            raw_fields = [f.strip() for f in re.split(r"[,\s]+", m.group(1)) if f.strip()]
            group_cols = [_safe_col(f) for f in raw_fields]
            group_by = group_cols
            select_parts = group_cols + ["count(*) as count"]
            has_stats = True

        # ---- sort ----------------------------------------------------------
        elif cmd == "sort":
            order_by = []
            for part in re.split(r",\s*", args):
                part = part.strip()
                if not part:
                    continue
                if part.startswith("-"):
                    col = _safe_col(part[1:])
                    order_by.append(f"{col} DESC")
                elif part.startswith("+"):
                    col = _safe_col(part[1:])
                    order_by.append(f"{col} ASC")
                else:
                    col = _safe_col(part)
                    order_by.append(f"{col} ASC")

        # ---- head ----------------------------------------------------------
        elif cmd == "head":
            try:
                limit_n = max(1, min(int(args), 5000))
            except ValueError:
                raise ValueError("Usage: | head <number>  e.g. | head 20")

        # ---- table ---------------------------------------------------------
        elif cmd == "table":
            raw_cols = re.split(r"[\s,]+", args.strip())
            table_cols = [_safe_col(c) for c in raw_cols if c.strip()]
            if not table_cols:
                raise ValueError("Usage: | table <field1> [<field2> ...]")
            select_parts = table_cols

        # ---- dedup ---------------------------------------------------------
        elif cmd == "dedup":
            col_name = args.split()[0] if args.split() else ""
            if not col_name:
                raise ValueError("Usage: | dedup <field>")
            dedup_col = _safe_col(col_name)

        # ---- where ---------------------------------------------------------
        elif cmd == "where":
            # Simple: field="value" or field='value' or field=value
            wm = re.match(r'(\w+)\s*=\s*["\']?([^"\']+)["\']?', args)
            if not wm:
                raise ValueError(
                    f"Unsupported where syntax: '{args}'\n"
                    "Usage: | where field=\"value\""
                )
            wf = _safe_col(wm.group(1))
            wv = wm.group(2).strip()
            _extra_where.append(f"{wf} = {ph}")
            _extra_params.append(wv)

        else:
            # Friendly suggestion for common mistakes
            suggestions = {
                "eval": "eval is not supported in SPL-lite. Use | table to project columns.",
                "lookup": "lookup is not supported in SPL-lite.",
                "regex": "Use | where description=\"keyword\" for pattern filtering.",
                "count": "Did you mean: | stats count by <field> ?",
                "group": "Did you mean: | stats count by <field> ?",
            }
            hint = suggestions.get(cmd, "")
            msg = f"Unknown command '{cmd}'."
            if hint:
                msg += f" {hint}"
            raise ValueError(msg)

    # Apply dedup via GROUP BY (if not already grouping)
    if dedup_col and not group_by:
        group_by = [dedup_col]
        # keep only the dedup col + first value of others via MIN()
        non_dedup = [c for c in select_parts if c != dedup_col and "count(*)" not in c]
        select_parts = [dedup_col] + [f"min({c}) as {c}" for c in non_dedup]

    # Merge all WHERE clauses
    all_where = where_clauses + _extra_where
    all_params = params + _extra_params

    # ── Build SQL ───────────────────────────────────────────────────────────
    select_str = ", ".join(select_parts)
    where_str = ("WHERE " + " AND ".join(all_where)) if all_where else ""
    group_str = f"GROUP BY {', '.join(group_by)}" if group_by else ""

    if order_by:
        order_str = "ORDER BY " + ", ".join(order_by)
    elif has_stats:
        order_str = "ORDER BY count DESC"
    else:
        order_str = "ORDER BY created_at DESC"

    if has_stats and limit_n > MAX_STATS_GROUPS:
        raise ValueError(
            f"| stats count by queries are limited to {MAX_STATS_GROUPS} distinct groups. "
            "Narrow with earliest=-24h or add | head N (max 500)."
        )

    limit_str = f"LIMIT {limit_n}"

    sql_parts = ["SELECT", select_str, "FROM siem_events"]
    if where_str:
        sql_parts.append(where_str)
    if group_str:
        sql_parts.append(group_str)
    sql_parts.append(order_str)
    sql_parts.append(limit_str)

    sql = " ".join(sql_parts)

    # ── Determine display columns ───────────────────────────────────────────
    display_cols: list[str] = []
    for p in select_parts:
        p_low = p.lower()
        if p_low == "count(*) as count":
            display_cols.append("count")
        elif " as " in p_low:
            display_cols.append(p_low.split(" as ")[-1].strip())
        else:
            display_cols.append(p.strip())

    # ── Human explanation ───────────────────────────────────────────────────
    explanation = _build_explanation(
        keywords, all_where, group_by, order_by, limit_n, has_stats
    )

    return {
        "sql": sql,
        "params": all_params,
        "columns": display_cols,
        "explanation": explanation,
        "error": None,
    }


def _build_explanation(keywords, where_clauses, group_by, order_by, limit, has_stats):
    parts = []
    if keywords:
        parts.append(f"Search: \"{', '.join(keywords)}\"")
    filter_count = sum(
        1 for c in where_clauses
        if not c.startswith("(description LIKE") and "created_at" not in c
    )
    time_filters = [c for c in where_clauses if "created_at" in c]
    if time_filters:
        parts.append("Time-filtered")
    if filter_count > 0:
        parts.append(f"{filter_count} field filter{'s' if filter_count > 1 else ''}")
    if group_by:
        parts.append(f"Grouped by {', '.join(group_by)}")
    if has_stats:
        parts.append("Counting per group")
    if order_by:
        parts.append(f"Sorted by {', '.join(order_by)}")
    parts.append(f"Limit {limit}")
    return " · ".join(parts) if parts else f"All events · Limit {limit}"


# ---------------------------------------------------------------------------
# Example queries (shown in the UI)
# ---------------------------------------------------------------------------
EXAMPLE_QUERIES = [
    {
        "label": "Top brute-force IPs",
        "query": "event_type=logon_failed earliest=-24h | stats count by src_ip | sort -count | head 10",
        "description": "Which source IPs have the most failed logins today?",
    },
    {
        "label": "Critical events (1h)",
        "query": "severity=CRITICAL earliest=-1h | table host event_type description",
        "description": "All CRITICAL severity events in the last hour",
    },
    {
        "label": "Firewall drops by IP",
        "query": "source=firewall earliest=-24h | stats count by src_ip | sort -count | head 20",
        "description": "Top blocked source IPs from the Windows Firewall log",
    },
    {
        "label": "Admin account activity",
        "query": "user_account=admin | sort -created_at | head 25",
        "description": "Recent events involving the admin account",
        },
    {
        "label": "Unique hosts seen",
        "query": "earliest=-7d | dedup host | table host src_ip event_type created_at",
        "description": "Distinct hosts that appeared in the last 7 days",
    },
    {
        "label": "New service installs",
        "query": "event_type=service_installed | table host user_account description created_at",
        "description": "Potential persistence via new service installs (MITRE T1543)",
    },
    {
        "label": "CRITICAL + HIGH today",
        "query": "severity=CRITICAL earliest=-24h | head 50",
        "description": "Start here each morning — priority events from the last 24h",
    },
    {
        "label": "Logins per user (7d)",
        "query": "event_type=logon_success earliest=-7d | stats count by user_account | sort -count",
        "description": "Who is logging in most frequently? Spot rogue accounts.",
    },
]
