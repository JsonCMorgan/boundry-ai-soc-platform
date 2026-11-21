"""
Job Skills board — proficient vs developing vs adjacent recommendations.

Eras: foundation (classic L1) → tomorrow (SOAR/AI oversight) → owner (MSSP ops).
Signals come from Career training tables. Work next boosts tomorrow/owner after
foundation greens.
"""

from __future__ import annotations

from typing import Any, Callable

_PROFICIENT_MIN_PASSES = 2
_PROFICIENT_MIN_SCORE = 70
_DEVELOPING_MIN_ATTEMPTS = 1

# Era boost when ranking Work next (after any foundation proficient)
_ERA_BOOST = {"foundation": 0.0, "tomorrow": 1.25, "owner": 1.0}

FetchOne = Callable[..., dict | None]
FetchAll = Callable[..., list[dict]]

ERA_LABELS = {
    "foundation": "Foundation",
    "tomorrow": "Tomorrow",
    "owner": "Owner",
}

SKILLS: list[dict[str, Any]] = [
    {
        "id": "secplus_fundamentals",
        "name": "Security+ fundamentals",
        "era": "foundation",
        "blurb": "CIA, controls, IAM, crypto, IR phases — exam + desk vocabulary.",
        "href": "/career/secplus",
        "signal": "secplus",
        "pairs_with": ["siem_spl", "email_triage", "identity_alerts", "interview_talk", "ops_metrics"],
        "jd_keywords": ["Security+", "fundamentals", "risk", "controls"],
    },
    {
        "id": "siem_spl",
        "name": "SIEM search (SPL)",
        "era": "foundation",
        "blurb": "Filter, stats, and table the way Splunk-style desks expect.",
        "href": "/career/spl",
        "signal": "spl",
        "pairs_with": ["siem_kql", "log_literacy", "shift_triage", "intel_enrich", "detection_tune"],
        "jd_keywords": ["SIEM", "Splunk", "SPL", "log analysis"],
    },
    {
        "id": "siem_kql",
        "name": "KQL / Sentinel mental model",
        "era": "foundation",
        "blurb": "Microsoft-heavy MSSP language: tables, joins, hunting mindset.",
        "href": "/career/kql",
        "signal": "kql",
        "pairs_with": ["sentinel_workspace", "identity_alerts", "siem_spl", "detection_tune"],
        "jd_keywords": ["KQL", "Sentinel", "Microsoft", "hunting"],
    },
    {
        "id": "shift_triage",
        "name": "Alert queue / shift triage",
        "era": "foundation",
        "blurb": "True vs false positive, dispositions, multi-client SLA pressure.",
        "href": "/career/shift",
        "signal": "shift",
        "pairs_with": ["ticket_hygiene", "soar_chain", "ai_oversight", "detection_tune"],
        "jd_keywords": ["triage", "SOC", "queue", "escalation"],
    },
    {
        "id": "email_triage",
        "name": "Phishing / BEC triage",
        "era": "foundation",
        "blurb": "Headers, auth results, impersonation — daily L1 work.",
        "href": "/career/email",
        "signal": "email",
        "pairs_with": ["intel_enrich", "identity_alerts", "comms_notes", "soar_chain"],
        "jd_keywords": ["phishing", "BEC", "email security"],
    },
    {
        "id": "edr_console",
        "name": "EDR console mental model",
        "era": "foundation",
        "blurb": "Process tree, isolate vs FP, timeline reading without a real tenant.",
        "href": "/career/edr",
        "signal": "edr",
        "pairs_with": ["log_literacy", "intel_enrich", "soar_chain", "ai_oversight"],
        "jd_keywords": ["EDR", "Defender", "endpoint", "isolate"],
    },
    {
        "id": "log_literacy",
        "name": "Log source literacy",
        "era": "foundation",
        "blurb": "4625/4688, firewall, proxy, M365 — name the evidence.",
        "href": "/career/logs",
        "signal": "logs",
        "pairs_with": ["siem_spl", "siem_kql", "automation_lite", "detection_tune"],
        "jd_keywords": ["Windows events", "firewall logs", "evidence"],
    },
    {
        "id": "intel_enrich",
        "name": "IOC enrichment",
        "era": "foundation",
        "blurb": "Lookup before escalate; write what you found into the ticket.",
        "href": "/career/intel",
        "signal": "intel",
        "pairs_with": ["soar_chain", "automation_lite", "ai_oversight", "ticket_hygiene"],
        "jd_keywords": ["threat intel", "IOC", "enrichment"],
    },
    {
        "id": "net_soc",
        "name": "Networking for SOC",
        "era": "foundation",
        "blurb": "Ports, DNS, HTTP, east-west — screening-list fluency.",
        "href": "/career/net",
        "signal": "net",
        "pairs_with": ["log_literacy", "edr_console", "siem_spl", "vuln_triage"],
        "jd_keywords": ["networking", "DNS", "TCP", "ports"],
    },
    {
        "id": "vuln_triage",
        "name": "Vulnerability triage",
        "era": "foundation",
        "blurb": "CVSS vs exploitability vs asset criticality to ticket priority.",
        "href": "/career/vuln",
        "signal": "vuln",
        "pairs_with": ["ticket_hygiene", "net_soc", "ops_metrics"],
        "jd_keywords": ["vulnerability", "CVSS", "patch"],
    },
    {
        "id": "sentinel_workspace",
        "name": "Sentinel workspace blades",
        "era": "foundation",
        "blurb": "Incidents, entities, hunting — beyond syntax drills.",
        "href": "/career/sentinel",
        "signal": "sentinel",
        "pairs_with": ["siem_kql", "identity_alerts", "ai_oversight"],
        "jd_keywords": ["Sentinel", "incidents", "entities"],
    },
    {
        "id": "identity_alerts",
        "name": "Identity / Entra alerts",
        "era": "foundation",
        "blurb": "Spray, impossible travel, MFA, Conditional Access outcomes.",
        "href": "/career/entra",
        "signal": "entra",
        "pairs_with": ["email_triage", "siem_kql", "soar_chain", "ai_oversight"],
        "jd_keywords": ["Entra", "identity", "MFA", "Conditional Access"],
    },
    {
        "id": "interview_talk",
        "name": "Interview walkthroughs",
        "era": "foundation",
        "blurb": "Say the case out loud: validate, decide, escalate or close.",
        "href": "/career/interview",
        "signal": "interview",
        "pairs_with": ["ticket_hygiene", "comms_notes", "ops_metrics"],
        "jd_keywords": ["interview", "communication", "escalation"],
    },
    {
        "id": "comms_notes",
        "name": "Stakeholder comms",
        "era": "foundation",
        "blurb": "User callbacks, client updates, Tier-2 escalate notes without overclaim.",
        "href": "/career/comms",
        "signal": "comms",
        "pairs_with": ["interview_talk", "ticket_hygiene", "automation_policy"],
        "jd_keywords": ["communication", "client updates", "escalation notes"],
    },
    {
        "id": "ticket_hygiene",
        "name": "Ticket / case documentation",
        "era": "foundation",
        "blurb": "SLA-aware notes, summary, next steps — MSSP ticket muscle.",
        "href": "/career/shift",
        "signal": "portfolio",
        "pairs_with": ["shift_triage", "soar_chain", "ops_metrics"],
        "jd_keywords": ["ServiceNow", "ticketing", "documentation"],
    },
    {
        "id": "soc_floor",
        "name": "Live SOC floor (/soc)",
        "era": "foundation",
        "blurb": "Real + Practice cases, handoffs, floor discipline.",
        "href": "/soc",
        "signal": "soc_floor",
        "pairs_with": ["shift_triage", "soar_chain", "automation_policy", "ops_metrics"],
        "jd_keywords": ["SOC operations", "handoff", "case management"],
    },
    # —— Tomorrow ——
    {
        "id": "soar_chain",
        "name": "SOAR enrich → contain chain",
        "era": "tomorrow",
        "blurb": "Multi-step playbook with human gates: enrich, propose, approve/deny, ticket note.",
        "href": "/career/soar",
        "signal": "soar",
        "pairs_with": ["ai_oversight", "automation_policy", "detection_tune", "intel_enrich"],
        "jd_keywords": ["SOAR", "playbooks", "orchestration", "human-in-the-loop"],
    },
    {
        "id": "ai_oversight",
        "name": "AI / agent verdict oversight",
        "era": "tomorrow",
        "blurb": "Validate or override an automated triage verdict with evidence (local stubs only).",
        "href": "/career/oversight",
        "signal": "oversight",
        "pairs_with": ["soar_chain", "detection_tune", "shift_triage", "automation_policy"],
        "jd_keywords": ["AI SOC", "agent oversight", "validation", "exception handling"],
    },
    {
        "id": "detection_tune",
        "name": "Tune or tolerate",
        "era": "tomorrow",
        "blurb": "After noisy FPs: tune the rule, tolerate with reason, or escalate to detection owner.",
        "href": "/career/tune",
        "signal": "tune",
        "pairs_with": ["siem_spl", "siem_kql", "ai_oversight", "ops_metrics"],
        "jd_keywords": ["detection tuning", "false positives", "use cases"],
    },
    {
        "id": "automation_lite",
        "name": "Automation lite",
        "era": "tomorrow",
        "blurb": "Safe local snippets to parse IOCs and format ticket notes (no remote exploit content).",
        "href": "/career/automation",
        "signal": "automation",
        "pairs_with": ["intel_enrich", "soar_chain", "ticket_hygiene"],
        "jd_keywords": ["PowerShell", "Python", "enrichment scripts"],
    },
    # —— Owner ——
    {
        "id": "ops_metrics",
        "name": "Ops metrics literacy",
        "era": "owner",
        "blurb": "MTTD/MTTR, FP rate, shift quality — speak client QBR language without fake MDR claims.",
        "href": "/career/metrics",
        "signal": "metrics",
        "pairs_with": ["automation_policy", "soc_floor", "comms_notes"],
        "jd_keywords": ["MTTD", "MTTR", "FP rate", "KPI"],
    },
    {
        "id": "automation_policy",
        "name": "Automation policy (per tenant)",
        "era": "owner",
        "blurb": "Decide auto-enrich vs approve-contain vs never-auto for each Practice client.",
        "href": "/career/automation-policy",
        "signal": "policy",
        "pairs_with": ["soar_chain", "ai_oversight", "ops_metrics", "soc_floor"],
        "jd_keywords": ["MSSP", "multi-tenant", "governance", "human gate"],
    },
]


def _attempt_stats(
    fetchall: FetchAll,
    ph: str,
    table: str,
    analyst_id: int,
) -> dict[str, int | float]:
    """Aggregate attempts/passes/avg score for a career_*_attempts table."""
    try:
        rows = fetchall(
            f"SELECT score_pct, passed FROM {table} WHERE analyst_id = {ph}",
            (analyst_id,),
        )
    except Exception:
        rows = []
    if not rows:
        return {"attempts": 0, "passes": 0, "avg_score": 0.0, "best": 0}
    attempts = len(rows)
    passes = sum(1 for r in rows if int(r.get("passed") or 0) == 1)
    scores = [int(r.get("score_pct") or 0) for r in rows]
    return {
        "attempts": attempts,
        "passes": passes,
        "avg_score": sum(scores) / attempts,
        "best": max(scores),
    }


def gather_signals(
    fetchone: FetchOne,
    fetchall: FetchAll,
    ph: str,
    analyst_id: int,
    *,
    secplus_passed_n: int = 0,
    secplus_total: int = 1,
    spl_lessons_done: int = 0,
    spl_lessons_total: int = 1,
    spl_quiz_passed: bool = False,
    kql_quizzes_done: int = 0,
    kql_quizzes_total: int = 1,
    net_quizzes_done: int = 0,
    net_quizzes_total: int = 1,
    interview_guided: int = 0,
    interview_coached: int = 0,
    interview_live: int = 0,
    interview_total: int = 1,
) -> dict[str, dict[str, Any]]:
    """Collect per-skill raw signals from DB + prove-it style counts."""
    email = _attempt_stats(fetchall, ph, "career_email_attempts", analyst_id)
    edr = _attempt_stats(fetchall, ph, "career_edr_attempts", analyst_id)
    logs = _attempt_stats(fetchall, ph, "career_logs_attempts", analyst_id)
    intel = _attempt_stats(fetchall, ph, "career_intel_attempts", analyst_id)
    vuln = _attempt_stats(fetchall, ph, "career_vuln_attempts", analyst_id)
    sentinel = _attempt_stats(fetchall, ph, "career_sentinel_attempts", analyst_id)
    entra = _attempt_stats(fetchall, ph, "career_entra_attempts", analyst_id)
    net_drill = _attempt_stats(fetchall, ph, "career_net_attempts", analyst_id)

    shift = fetchone(
        f"SELECT COUNT(*) AS c, COALESCE(AVG(score_pct),0) AS avg_pct "
        f"FROM career_shift_sessions WHERE analyst_id = {ph} AND status = 'complete'",
        (analyst_id,),
    ) or {}
    shifts_n = int(shift.get("c") or 0)
    shift_avg = float(shift.get("avg_pct") or 0)

    port = fetchone(
        f"SELECT COUNT(*) AS c FROM career_portfolio_cases WHERE analyst_id = {ph}",
        (analyst_id,),
    ) or {}
    port_n = int(port.get("c") or 0)

    try:
        soc = fetchone(
            f"SELECT COUNT(*) AS c FROM soc_shift_sessions "
            f"WHERE analyst_id = {ph} AND ended_at IS NOT NULL",
            (analyst_id,),
        )
        soc_n = int((soc or {}).get("c") or 0)
    except Exception:
        soc_n = 0

    secplus_pct = round(100 * secplus_passed_n / max(secplus_total, 1))
    spl_pct = round(100 * spl_lessons_done / max(spl_lessons_total, 1))
    if spl_quiz_passed:
        spl_pct = max(spl_pct, 85)
    kql_pct = round(100 * kql_quizzes_done / max(kql_quizzes_total, 1))
    net_pct = round(100 * net_quizzes_done / max(net_quizzes_total, 1))
    if net_drill["attempts"]:
        net_pct = max(net_pct, min(100, int(net_drill["avg_score"])))

    iv_reps = interview_guided + interview_coached + interview_live
    iv_pct = round(100 * min(iv_reps, interview_total * 2) / max(interview_total * 2, 1))
    if interview_live >= 3:
        iv_pct = max(iv_pct, 75)

    def from_attempts(stats: dict[str, int | float]) -> dict[str, Any]:
        return {
            "attempts": int(stats["attempts"]),
            "passes": int(stats["passes"]),
            "score": float(stats["avg_score"]),
            "best": int(stats["best"]),
        }

    return {
        "secplus": {
            "attempts": secplus_passed_n,
            "passes": secplus_passed_n,
            "score": float(secplus_pct),
            "best": secplus_pct,
            "coverage_pct": secplus_pct,
        },
        "spl": {
            "attempts": spl_lessons_done,
            "passes": spl_lessons_done if spl_quiz_passed else max(0, spl_lessons_done // 2),
            "score": float(spl_pct),
            "best": spl_pct,
        },
        "kql": {
            "attempts": kql_quizzes_done,
            "passes": kql_quizzes_done,
            "score": float(kql_pct),
            "best": kql_pct,
        },
        "shift": {
            "attempts": shifts_n,
            "passes": shifts_n if shift_avg >= _PROFICIENT_MIN_SCORE else max(0, shifts_n // 2),
            "score": shift_avg,
            "best": int(shift_avg),
        },
        "email": from_attempts(email),
        "edr": from_attempts(edr),
        "logs": from_attempts(logs),
        "intel": from_attempts(intel),
        "vuln": from_attempts(vuln),
        "sentinel": from_attempts(sentinel),
        "entra": from_attempts(entra),
        "net": {
            "attempts": max(net_quizzes_done, int(net_drill["attempts"])),
            "passes": max(net_quizzes_done, int(net_drill["passes"])),
            "score": float(net_pct),
            "best": max(net_pct, int(net_drill["best"])),
        },
        "interview": {
            "attempts": iv_reps,
            "passes": interview_live + interview_coached,
            "score": float(iv_pct),
            "best": iv_pct,
        },
        "portfolio": {
            "attempts": port_n,
            "passes": port_n,
            "score": float(min(100, port_n * 25)),
            "best": min(100, port_n * 25),
        },
        "soc_floor": {
            "attempts": soc_n,
            "passes": soc_n,
            "score": float(min(100, soc_n * 20)),
            "best": min(100, soc_n * 20),
        },
        "comms": from_attempts(_attempt_stats(fetchall, ph, "career_comms_attempts", analyst_id)),
        "soar": from_attempts(_attempt_stats(fetchall, ph, "career_soar_attempts", analyst_id)),
        "oversight": from_attempts(
            _attempt_stats(fetchall, ph, "career_oversight_attempts", analyst_id)
        ),
        "tune": from_attempts(_attempt_stats(fetchall, ph, "career_tune_attempts", analyst_id)),
        "automation": from_attempts(
            _attempt_stats(fetchall, ph, "career_automation_attempts", analyst_id)
        ),
        "metrics": from_attempts(
            _attempt_stats(fetchall, ph, "career_metrics_attempts", analyst_id)
        ),
        "policy": from_attempts(
            _attempt_stats(fetchall, ph, "career_policy_attempts", analyst_id)
        ),
    }


def _classify(sig: dict[str, Any]) -> str:
    """Return proficient | developing | untouched."""
    attempts = int(sig.get("attempts") or 0)
    passes = int(sig.get("passes") or 0)
    score = float(sig.get("score") or 0)
    coverage = sig.get("coverage_pct")

    if coverage is not None:
        if float(coverage) >= 70 and passes >= max(3, _PROFICIENT_MIN_PASSES):
            return "proficient"
        if attempts > 0 or float(coverage) > 0:
            return "developing"
        return "untouched"

    if (
        passes >= _PROFICIENT_MIN_PASSES
        and score >= _PROFICIENT_MIN_SCORE
        and attempts >= _PROFICIENT_MIN_PASSES
    ):
        return "proficient"
    if attempts >= 5 and score >= _PROFICIENT_MIN_SCORE:
        return "proficient"
    if attempts >= 3 and passes >= 3 and score >= 65:
        return "proficient"
    if attempts >= _DEVELOPING_MIN_ATTEMPTS or score > 0:
        return "developing"
    return "untouched"


def build_skill_board(signals: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Build proficient / developing / recommended with era-aware Work next."""
    by_id = {s["id"]: s for s in SKILLS}
    rows: list[dict[str, Any]] = []

    for skill in SKILLS:
        sig = signals.get(skill["signal"], {})
        status = _classify(sig)
        era = skill.get("era") or "foundation"
        rows.append({
            **skill,
            "era": era,
            "era_label": ERA_LABELS.get(era, era),
            "status": status,
            "attempts": int(sig.get("attempts") or 0),
            "passes": int(sig.get("passes") or 0),
            "score": round(float(sig.get("score") or 0)),
            "detail": _detail_line(status, sig),
        })

    proficient = [r for r in rows if r["status"] == "proficient"]
    developing = [r for r in rows if r["status"] == "developing"]
    untouched = [r for r in rows if r["status"] == "untouched"]
    foundation_ready = any(
        r["status"] == "proficient" and r.get("era") == "foundation" for r in rows
    )

    adj_score: dict[str, float] = {}
    adj_from: dict[str, list[str]] = {}
    for p in proficient:
        for nid in p.get("pairs_with") or []:
            if nid not in by_id:
                continue
            target = next((r for r in rows if r["id"] == nid), None)
            if not target or target["status"] == "proficient":
                continue
            score = 1.0
            if target["status"] == "developing":
                score += 0.5 + (target["score"] / 200.0)
            if foundation_ready:
                score += _ERA_BOOST.get(target.get("era") or "foundation", 0.0)
            adj_score[nid] = adj_score.get(nid, 0) + score
            adj_from.setdefault(nid, []).append(p["name"])

    # Soft pull toward tomorrow after any foundation green even without direct pair
    if foundation_ready:
        for r in rows:
            if r["status"] == "proficient":
                continue
            if r.get("era") in ("tomorrow", "owner") and r["id"] not in adj_score:
                adj_score[r["id"]] = 0.4 if r["era"] == "tomorrow" else 0.25
                adj_from.setdefault(r["id"], []).append("foundation path")

    recommended: list[dict[str, Any]] = []
    for nid, score in sorted(adj_score.items(), key=lambda x: (-x[1], x[0])):
        row = next(r for r in rows if r["id"] == nid)
        era_bit = f" · {row.get('era_label', '')}"
        why = "Pairs with: " + ", ".join(adj_from.get(nid, [])[:3]) + era_bit
        recommended.append({
            **row,
            "why": why,
            "pair_strength": round(score, 1),
        })

    if not recommended and not proficient:
        for sid in ("secplus_fundamentals", "shift_triage", "siem_spl"):
            row = next(r for r in rows if r["id"] == sid)
            if row["status"] != "proficient":
                recommended.append({
                    **row,
                    "why": "Start here for the Sec+ to desk-ready path (PRD).",
                    "pair_strength": 0,
                })

    era_counts = {
        "foundation": sum(1 for r in proficient if r.get("era") == "foundation"),
        "tomorrow": sum(1 for r in proficient if r.get("era") == "tomorrow"),
        "owner": sum(1 for r in proficient if r.get("era") == "owner"),
    }

    return {
        "proficient": sorted(proficient, key=lambda r: (-r["score"], r["name"])),
        "developing": sorted(developing, key=lambda r: (-r["score"], r["name"])),
        "untouched": sorted(untouched, key=lambda r: r["name"]),
        "recommended": recommended[:6],
        "counts": {
            "proficient": len(proficient),
            "developing": len(developing),
            "untouched": len(untouched),
            "total": len(rows),
            "era": era_counts,
        },
        "all": rows,
        "era_labels": ERA_LABELS,
    }


def _detail_line(status: str, sig: dict[str, Any]) -> str:
    """Short status line for UI."""
    attempts = int(sig.get("attempts") or 0)
    score = round(float(sig.get("score") or 0))
    if status == "proficient":
        return f"Proficient · score ~{score}% · {attempts} reps"
    if status == "developing":
        return f"Building · score ~{score}% · {attempts} reps"
    return "Not started in Hub yet"
