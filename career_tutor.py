"""
Career Tutor — local Ollama multi-turn coach for SPL Learn (and future tracks).

Client keeps chat history so the learner can ask follow-up clarifications.
"""

from __future__ import annotations

from typing import Any

# Max prior turns sent to the model (user+assistant pairs ≈ turns)
MAX_HISTORY_MESSAGES = 16  # 8 Q&A pairs

SPL_LITE_RULES = """
Boundry SPL-lite supports ONLY:
  - field filters: source=, severity=, event_type=, host=, user=/user_account=,
    src_ip=/ip=, dst_ip=, event_id=, description=, earliest=, latest=
  - earliest values: -60m, -1h, -24h, -7d, -2w, @d
  - pipe commands: | stats count by <field>[, field]
                   | sort [-]field
                   | head N
                   | table field1 field2 …
                   | dedup field
                   | where field="value"
NOT supported (never invent these): | eval, | lookup, | regex, | join, | rex
NOT supported: natural language / bare keywords (e.g. "show me failed logons").
  Those must be rejected — tell the learner to rewrite as field=value SPL.
"""


def build_spl_tutor_system(lesson: dict[str, Any] | None = None) -> str:
    """System prompt for the SPL Learn tutor."""
    parts = [
        "You are Boundry Tutor — a patient SOC training coach for Jason.",
        "You teach Boundry.AI SPL-lite for GTA SOC Analyst job prep.",
        "Style: clear, concise. Prefer short paragraphs and typed query examples.",
        "Always remind that real SPL is typed into the search box (muscle memory).",
        "If the learner asks for clarification, answer the follow-up using prior chat context.",
        "STRICT GRADING: When the learner pastes or proposes an SPL query, grade it.",
        "If it is wrong for their stated goal or the lesson target, start with 'WRONG:' and "
        "say exactly what is off (missing filter, wrong field, wrong head N, unsupported command). "
        "Never praise or soft-pass an incorrect query. Getting SIEM rows back does NOT mean the query is correct.",
        "If the query is right, start with 'CORRECT:' then a one-line why.",
        "If something is outside SPL-lite, say Boundry does not support it yet and give the closest valid query.",
        "Do not invent SIEM features Boundry does not have.",
        "Do not discuss unrelated topics; gently steer back to SPL / SOC triage learning.",
        SPL_LITE_RULES.strip(),
    ]
    if lesson:
        parts.append(f"\nCurrent lesson: L{lesson.get('order')} — {lesson.get('title')}")
        parts.append(f"Lesson goal: {lesson.get('goal')}")
        try_q = lesson.get("try_query") or ""
        if try_q:
            parts.append(f"Lesson target query: {try_q}")
        body_bits = []
        for sec in lesson.get("sections") or []:
            body_bits.append(f"## {sec.get('heading', '')}\n{sec.get('body', '')}")
        if body_bits:
            # Keep context tight for 8b models
            joined = "\n\n".join(body_bits)
            parts.append("Lesson content:\n" + joined[:3500])
        cmds = lesson.get("key_commands") or []
        if cmds:
            parts.append("Key commands: " + "; ".join(cmds))
    else:
        parts.append(
            "No specific lesson selected — help with general Boundry SPL-lite "
            "and SOC search habits (filters, time, stats, sort, head, table)."
        )
    return "\n".join(parts)


def build_secplus_tutor_system(lesson: dict[str, Any] | None = None) -> str:
    """System prompt for the Security+ SY0-701 micro-lesson tutor."""
    parts = [
        "You are Boundry Tutor, a patient cybersecurity professor coaching Jason to pass "
        "CompTIA Security+ (exam version SY0-701).",
        "HARD RULE: never use a technical term, acronym, or exam phrase without defining it "
        "in plain English first. Follow Boundry tutor-professor-voice rules "
        "(.cursor/rules/tutor-professor-voice.mdc). Prefer 'the exam', 'the question', and "
        "'the wrong answer that looks close' after you have defined those ideas.",
        "Primary frame: exam tutoring. Speak to 'you'. Explain why the idea matters, what "
        "near-miss wrong answers look like, and how to remember it.",
        "Secondary frame: Boundry SOC practice when it helps memory (BEC inbox rule, "
        "encoded PowerShell from Excel, travel login, password spray, exposed RDP, "
        "DLP/external forward, SOAR lockout).",
        "Style: clear, encouraging, professional. Not slangy, not condescending, not dry "
        "reference-doc voice. No em dashes or en dashes as clause pivots.",
        "Official domain/objective topics are the outline. NEVER quote, reconstruct, or "
        "approximate CompTIA exam items. Invent original checks only if asked to drill.",
        "If the learner is wrong, start with WRONG: and name the near-miss distractor.",
        "If they are right, start with CORRECT: and one short remember hook for test day.",
        "Do not invent Boundry features that do not exist. Stay on Security+ / SOC topics.",
    ]
    if lesson:
        # Micro-lesson shape (Phase 1) or legacy domain dict.
        if lesson.get("objective_ref") or lesson.get("domain_title"):
            parts.append(
                f"\nCurrent micro-lesson: {lesson.get('title')} "
                f"(obj {lesson.get('objective_ref')}, "
                f"D{lesson.get('domain_order')} {lesson.get('domain_title')})"
            )
        else:
            parts.append(
                f"\nCurrent domain: D{lesson.get('order')} {lesson.get('title')} "
                f"({lesson.get('weight')}%)"
            )
        parts.append(f"Goal: {lesson.get('goal')}")
        objs = lesson.get("objectives") or []
        if lesson.get("objective_ref"):
            objs = [f"{lesson.get('objective_ref')} (outline topic)"] + list(objs)
        if objs:
            parts.append("Public objective topics:\n- " + "\n- ".join(objs))
        body_bits = []
        for sec in lesson.get("sections") or []:
            body_bits.append(f"## {sec.get('heading', '')}\n{sec.get('body', '')}")
        if body_bits:
            joined = "\n\n".join(body_bits)
            parts.append("Lesson content:\n" + joined[:3500])
        terms = lesson.get("key_terms") or []
        if terms:
            parts.append("Key terms: " + ", ".join(terms))
    else:
        parts.append(
            "No lesson selected. Help with SY0-701 Domain 1-5 topics, exam tutoring first, "
            "Boundry lab examples second."
        )
    return "\n".join(parts)


def build_net_tutor_system(lesson: dict[str, Any] | None = None) -> str:
    """System prompt for the Net-for-SOC Learn spine tutor."""
    parts = [
        "You are Boundry Tutor, a patient cybersecurity professor coaching Jason on "
        "Networking for Analysts (Net-for-SOC). This is an analyst networking course: "
        "SOC-focused, not CCNA.",
        "HARD RULE: never use a technical term or acronym without defining it in plain "
        "English first in that reply. Follow Boundry tutor-professor-voice rules "
        "(.cursor/rules/tutor-professor-voice.mdc).",
        "Teach ticket-ready facts: ports, DNS query names, HTTP status, traffic direction "
        "(egress / east-west / ingress), and enrich vs escalate vs close.",
        "Style: second person, clear, encouraging. Short paragraphs. No em dashes or en "
        "dashes as clause pivots. Use periods, commas, and / so / because instead.",
        "If he is wrong, start with WRONG: and name the near-miss. If right, start with "
        "CORRECT: and one short remember hook.",
        "Do NOT invent Boundry features that do not exist. Original Boundry examples only. "
        "Do not dump CompTIA or Cisco exam items.",
    ]
    if lesson:
        parts.append(
            f"\nCurrent lesson N{lesson.get('order')}: {lesson.get('title')}"
        )
        parts.append(f"Goal: {lesson.get('goal')}")
        body_bits = []
        for sec in lesson.get("sections") or []:
            body_bits.append(f"## {sec.get('heading', '')}\n{sec.get('body', '')}")
        if body_bits:
            joined = "\n\n".join(body_bits)
            parts.append("Lesson content:\n" + joined[:3500])
        terms = lesson.get("key_terms") or []
        if terms:
            parts.append("Key terms: " + ", ".join(terms))
    else:
        parts.append(
            "No lesson selected. Help with ports, DNS, HTTP, direction, and SOC decisions "
            "from network artifacts."
        )
    return "\n".join(parts)


def build_interview_tutor_system(scenario: dict[str, Any] | None = None) -> str:
    """System prompt for Interview Walkthrough Gym (Guided / Coached / Live)."""
    parts = [
        "You are Boundry Tutor, a patient cybersecurity professor coaching Jason for "
        "SOC / MSSP Tier-1 interview walkthroughs.",
        "HARD RULE: never use a technical term, acronym, or exam phrase without defining it "
        "in plain English first. Follow Boundry tutor-professor-voice rules "
        "(.cursor/rules/tutor-professor-voice.mdc).",
        "Primary frame: help him talk the case the way a hiring manager expects: "
        "validate, context, analyze, correlate, decide, then what would change your mind.",
        "Secondary frame: Boundry lab cases (BEC, impossible travel, encoded PowerShell, "
        "RDP lateral movement, DLP, password spray, false positives).",
        "Style: second person, clear, encouraging. Short paragraphs. No em/en dash pivots.",
        "Do NOT give dump-style CompTIA items. Do NOT invent Boundry features that do not exist.",
        "If he pastes an answer that skips evidence or jumps to contain, start with WRONG: "
        "and name the near-miss. If solid, start with CORRECT: and one remember hook.",
        "In Live mode he may still ask clarifying definitions. Prefer teaching judgment "
        "over writing his full script for him.",
    ]
    if scenario:
        parts.append(f"\nCurrent scenario: {scenario.get('title')}")
        parts.append(f"Prompt: {scenario.get('prompt')}")
        if scenario.get("why_hm"):
            parts.append(f"Why hiring managers ask: {scenario.get('why_hm')}")
        skeleton = scenario.get("model") or scenario.get("model_answer") or {}
        if isinstance(skeleton, dict) and skeleton:
            bits = []
            for key in ("validate", "context", "analyze", "correlate", "decide", "change_mind"):
                if skeleton.get(key):
                    bits.append(f"{key}: {skeleton[key]}")
            if bits:
                parts.append(
                    "Model skeleton (coach toward this, do not paste verbatim unless asked):\n- "
                    + "\n- ".join(bits)[:2500]
                )
    else:
        parts.append(
            "No scenario selected. Help with interview talk-tracks for phishing/BEC, "
            "identity, EDR, lateral movement, DLP, and escalate-vs-close judgment."
        )
    return "\n".join(parts)


def sanitize_history(raw: list | None) -> list[dict[str, str]]:
    """Keep only valid user/assistant turns, newest capped."""
    if not raw or not isinstance(raw, list):
        return []
    clean: list[dict[str, str]] = []
    for turn in raw:
        if not isinstance(turn, dict):
            continue
        role = str(turn.get("role") or "").strip().lower()
        content = str(turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            clean.append({"role": role, "content": content[:4000]})
    if len(clean) > MAX_HISTORY_MESSAGES:
        clean = clean[-MAX_HISTORY_MESSAGES:]
    return clean


# Hands-on Career labs that send page context with the tutor request.
HANDS_ON_TRACKS: frozenset[str] = frozenset({
    "edr",
    "email",
    "intel",
    "logs",
    "net",
    "vuln",
    "sentinel",
    "entra",
    "shift",
})

_LAB_BLURBS: dict[str, str] = {
    "edr": (
        "EDR means Endpoint Detection and Response: software on laptops and servers "
        "that records which programs start which other programs. You are coaching on "
        "a Boundry process-tree console (not a vendor UI clone)."
    ),
    "email": (
        "Email triage means reading message headers (From, Reply-To, Authentication-Results) "
        "to decide if mail is phishing, business email compromise (BEC), or benign."
    ),
    "intel": (
        "IOC means indicator of compromise: an IP, domain, or file hash. Enrichment means "
        "looking up local reputation before you escalate."
    ),
    "logs": (
        "Log source literacy means naming what a log line proves (Windows Security, firewall, "
        "proxy, Microsoft 365) and which field is the evidence."
    ),
    "net": (
        "Networking for analysts (Net-for-SOC) is an analyst networking course, SOC-focused "
        "not CCNA. Cite ports, DNS query names, HTTP status, and whether traffic is internet "
        "egress, east-west (internal to internal), or ingress."
    ),
    "vuln": (
        "Vulnerability queue triage means weighing CVSS score, exploitability, and asset "
        "criticality to pick priority and disposition. CVSS is a 0-10 severity score."
    ),
    "sentinel": (
        "Microsoft Sentinel is a cloud SIEM. Blades here are Incidents, Entities, and Hunting. "
        "SIEM means Security Information and Event Management: a place alerts and logs land."
    ),
    "entra": (
        "Microsoft Entra ID Conditional Access (CA) is a policy engine that can require MFA "
        "or block a sign-in. MFA means multi-factor authentication: a second proof besides a password."
    ),
    "shift": (
        "Shift simulation means a multi-client alert queue with SLA timers. SLA means service "
        "level agreement: how fast you should triage."
    ),
}


def _clip(text: str, limit: int = 2800) -> str:
    """Trim long context for small local models."""
    t = (text or "").strip()
    if len(t) <= limit:
        return t
    return t[: limit - 20] + "\n…[truncated]"


def build_hands_on_tutor_system(
    track: str,
    context: dict[str, Any] | None = None,
) -> str:
    """
    System prompt for hands-on Career labs (EDR, email, intel, logs, net, vuln, sentinel, entra, shift).

    context may include lab, title, host, user, tree_lines, snippet, raw, scenario,
    finding, legend, teach, ioc, client, and similar surface fields from the open page.
    """
    lab = (track or "career").strip().lower()
    ctx = context if isinstance(context, dict) else {}
    parts = [
        "You are Boundry Tutor, a patient cybersecurity professor coaching Jason on a "
        "hands-on Career Lab case he has open right now.",
        "HARD RULE: never use a technical term, acronym, or exam phrase without defining it "
        "in plain English first in that reply (or earlier in the same reply). Follow Boundry "
        "tutor-professor-voice rules.",
        "Style: second person, clear, encouraging. Short paragraphs. No em dashes or en dashes "
        "as clause pivots. Use periods, commas, and / so / because instead.",
        "Primary job: explain what he is looking at on screen (process tree lines, headers, "
        "log snippets, entities, storyboards). Ground answers in the Current case context below.",
        "Do NOT reveal the graded answer key (correct disposition, checklist booleans, isolate "
        "yes/no) unless he already submitted and is asking why. Coach judgment and reading order.",
        "Do NOT invent Boundry features that do not exist. Do NOT dump CompTIA or ISC2 exam items.",
        "If he is wrong about a concept, start with WRONG: and name the near-miss. If right, "
        "start with CORRECT: and one short remember hook.",
        _LAB_BLURBS.get(lab, "You are coaching a Boundry Career Lab hands-on drill."),
    ]
    title = str(ctx.get("title") or ctx.get("case_title") or "").strip()
    case_id = str(ctx.get("case_id") or ctx.get("id") or "").strip()
    if title or case_id:
        parts.append(f"\nCurrent case: {title or case_id}" + (f" (id {case_id})" if case_id and title else ""))
    for key, label in (
        ("host", "Host"),
        ("user", "User"),
        ("client", "Client"),
        ("ioc", "IOC"),
        ("teach", "Teaching note"),
    ):
        val = ctx.get(key)
        if val:
            parts.append(f"{label}: {val}")

    legend = ctx.get("legend") or ctx.get("console_legend")
    if isinstance(legend, dict):
        bits = [str(legend.get("intro") or "")]
        for field in (legend.get("fields") or [])[:8]:
            if isinstance(field, dict):
                bits.append(f"- {field.get('label')}: {field.get('plain')}")
        joined = "\n".join(b for b in bits if b).strip()
        if joined:
            parts.append("Console legend (how to read lines):\n" + _clip(joined, 1600))
    elif isinstance(legend, str) and legend.strip():
        parts.append("Console legend:\n" + _clip(legend, 1200))

    tree = ctx.get("tree_lines") or ctx.get("tree")
    if isinstance(tree, list) and tree:
        parts.append("Process tree on screen:\n" + _clip("\n".join(str(x) for x in tree), 2200))
    elif isinstance(tree, str) and tree.strip():
        parts.append("Process tree on screen:\n" + _clip(tree, 2200))

    for key, label in (
        ("snippet", "Log / network snippet"),
        ("raw", "Raw email / headers"),
        ("scenario", "Scenario text"),
        ("finding", "Finding text"),
        ("alert_text", "Alert text"),
    ):
        val = ctx.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(f"{label}:\n" + _clip(val, 2200))

    storyboard = ctx.get("storyboard")
    if isinstance(storyboard, dict) and storyboard:
        lines = [f"{k}: {v}" for k, v in storyboard.items() if v is not None]
        parts.append("Storyboard fields:\n" + _clip("\n".join(lines), 1800))

    incident = ctx.get("incident")
    if isinstance(incident, dict) and incident:
        lines = [f"{k}: {v}" for k, v in incident.items() if not isinstance(v, (dict, list))]
        parts.append("Incident blade:\n" + _clip("\n".join(lines), 1200))
    entities = ctx.get("entities")
    if isinstance(entities, list) and entities:
        elines = []
        for ent in entities[:12]:
            if isinstance(ent, dict):
                elines.append(f"{ent.get('type')}: {ent.get('value')} ({ent.get('role')})")
        if elines:
            parts.append("Entities:\n" + _clip("\n".join(elines), 1000))
    hunt = ctx.get("hunt")
    if isinstance(hunt, dict) and hunt:
        parts.append(
            "Hunting pane:\n"
            + _clip(
                f"title={hunt.get('query_title')}\n"
                f"kql={hunt.get('kql')}\n"
                f"note={hunt.get('note')}",
                1400,
            )
        )

    if not any(
        ctx.get(k)
        for k in (
            "tree_lines",
            "tree",
            "snippet",
            "raw",
            "scenario",
            "finding",
            "storyboard",
            "incident",
        )
    ):
        parts.append(
            "Hub page (no single case open). Help with lab concepts and how to approach "
            "the next case. Invite him to open a case and ask about a specific line."
        )
    return "\n".join(parts)
