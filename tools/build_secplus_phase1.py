"""
Assemble Security+ Phase 1 curriculum → secplus_lessons.py + rewrite secplus_learn.py engine.

Run from repo root:
  python tools/build_secplus_phase1.py

Option C (MCQ parallel form / length bias):
  Choice overlays live in tools/_mcq_parallel_pack.json (q_id / practice_id → choices).
  Rebuild pack: python tools/_dump_mcq_for_rewrite.py
                 python tools/_rewrite_secplus_mcq_parallel.py --no-ollama
  Build applies the pack before letter rotation, then hard-fails on severe
  correct-longest bias (see tools/secplus_mcq_length_lint.py).
  Re-audit: python tools/_audit_secplus_mcq_length.py

VOICE GUIDE (Professor / tutor)
------------------------------
Canonical rule (always apply in Cursor):
  .cursor/rules/tutor-professor-voice.mdc

Gold standard lesson: tools/gen_secplus_d1.py → sp_d1_01_control_functions

Summary (keep in sync with that rule):
  #1 DEFINE BEFORE USE. Never open with undefined SY0-701 / distractor / stem / MFA / SIEM.
  Orient → define → short work-facing picture OR "Where you see this at work" →
  bridge "In Security+ terms, that is X." → technical specifics → beats → denser
  worked example → how to answer → common trap → remember → teach-back block.
  Skip fluffy metaphors. Prefer SOC/desk/hire-aligned pictures that map 1:1.
  Every Show-me ends with teach_back (explain aloud + define three + desk + trap).
  Second person. Plain English. ~15–20 min Show-me. No em/en dash pivots. No dumps.
  Prefer "the exam", "the question", "the wrong answer that looks close" after defining them.
  Boundry SOC examples are secondary memory hooks only.
  Depth packs / regenerator helpers: tools/_apply_option1_depth.py (D2-D5),
  D2/D3 Option 1 thicken: tools/_depth_packs_d23_thick.py,
  D4/D5 Option 1 thicken: tools/_depth_packs_d45_thick.py +
  tools/_depth_packs_d5_tail_thick.py, then build_secplus_phase1.py.
  Hand-expanded gold bar in tools/gen_secplus_d1.py.

Do NOT invent CompTIA dumps or copy official exam items. Official objective IDs
are the outline. CISSP teaching copy must follow the same define-before-use rule.
"""
from __future__ import annotations

import pprint
from typing import Any
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from secplus_mcq_length_lint import lint_mcq_banks  # noqa: E402

MCQ_PARALLEL_PACK = ROOT / "tools" / "_mcq_parallel_pack.json"

DOMAINS = [
    {
        "id": "d1_concepts", "order": 1, "weight": 16,
        "title": "General Security Concepts",
        "short": "CIA, controls, change, crypto", "color": "#2dd4bf",
        "goal": "Name control types and CIA/AAA cleanly under exam pressure.",
        "hub_note": "SY0-801 Domain 1 is 16%. Start here. Later domains assume this vocabulary.",
        "objectives": [
            "1.1 Explain security concepts and controls",
            "1.2 Given a scenario, demonstrate the impact of change management on security",
            "1.3 Explain the importance of using appropriate cryptographic solutions",
        ],
    },
    {
        "id": "d2_threats", "order": 2, "weight": 24,
        "title": "Threats, Vulnerabilities, and Attacks",
        "short": "Chars, actors, vectors, vulns, IOCs, AI", "color": "#ff8c00",
        "goal": "Pass Domain 2 by separating threat/vuln characteristics, actors, vectors, IOCs, and AI abuse.",
        "hub_note": "Heavy domain (24% on SY0-801). Mitigations moved to Domain 4; AI threats are new on 801.",
        "objectives": [
            "2.1 Explain characteristics of threats and vulnerabilities",
            "2.2 Describe common threat actors and motivations",
            "2.3 Describe threat vectors and sources",
            "2.4 Explain types of vulnerabilities and attack surfaces",
            "2.5 Given a scenario, analyze indicators of malicious activity",
            "2.6 Summarize threats and vulnerabilities associated with AI usage",
        ],
    },
    {
        "id": "d3_architecture", "order": 3, "weight": 19,
        "title": "Security Architecture",
        "short": "ZT, infra, data, resilience", "color": "#a78bfa",
        "goal": "Pass Domain 3 by choosing architecture that closes the path, not extra dashboards.",
        "hub_note": "Common trap: picking a detective-only answer when the question needs you to remove the attack path.",
        "objectives": [
            "3.1 Compare and contrast security implications of different architecture models",
            "3.2 Given a scenario, manage the security architecture to protect infrastructure",
            "3.3 Summarize concepts and strategies used to protect data",
            "3.4 Explain the importance of resilience and recovery in security architecture",
        ],
    },
    {
        "id": "d4_operations", "order": 4, "weight": 27,
        "title": "Security Operations",
        "short": "Mitigate, hunt, IR, IAM, SOAR", "color": "#00ff88",
        "goal": "Pass Domain 4 by applying mitigations, then alert → source → contain → ticket.",
        "hub_note": "Heaviest domain (27% on SY0-801). Includes mitigations moved from Domain 2.",
        "objectives": [
            "4.1 Given a scenario, apply mitigating controls, techniques, and solutions",
            "4.2 Explain security implications of proper asset management",
            "4.3 Given a scenario, perform tasks associated with vulnerability management",
            "4.4 Explain security alerting and monitoring concepts and tools",
            "4.5 Given a scenario, apply concepts related to identity and access management",
            "4.6 Given a scenario, apply automation and orchestration solutions",
            "4.7 Summarize concepts associated with incident response activities",
            "4.8 Given a scenario, use data and artifacts to support a security investigation",
        ],
    },
    {
        "id": "d5_oversight", "order": 5, "weight": 14,
        "title": "Security Program Management and Oversight",
        "short": "Gov, risk, vendors, awareness", "color": "#f472b6",
        "goal": "Pass Domain 5 by closing the loop: owner, risk treatment, vendor, awareness.",
        "hub_note": "Program layer after the ticket (14% on SY0-801). Remember: owner, treatment, vendor, awareness.",
        "objectives": [
            "5.1 Explain the importance of governance, risk, and compliance artifacts",
            "5.2 Explain the impact of risk management processes on security",
            "5.3 Explain assessment and management of third-party risk",
            "5.4 Summarize elements of effective security compliance",
            "5.5 Explain concepts associated with audit and assessment activities",
            "5.6 Given a scenario, apply security awareness concepts",
        ],
    },
]

JOB_CTAS = {
    "d1": [
        {"label": "Glossary", "href": "/glossary", "why": "Lock CIA / AAA / control-type terms."},
        {"label": "Interview Gym", "href": "/career/interview", "why": "Say control types on a case."},
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Name the control that failed."},
    ],
    "d2": [
        {"label": "Interview Gym", "href": "/career/interview", "why": "Brief spray vs BEC vs malware."},
        {"label": "Shift Sim", "href": "/career/shift", "why": "Grade live alert patterns."},
    ],
    "d3": [
        {"label": "Interview Gym", "href": "/career/interview", "why": "Architecture fixes for RDP / CA."},
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Write the control that should have existed."},
    ],
    "d4": [
        {"label": "Shift Sim", "href": "/career/shift", "why": "Practice the queue."},
        {"label": "SPL Learn", "href": "/career/spl", "why": "Hunt identity failures."},
        {"label": "KQL Learn", "href": "/career/kql", "why": "Sentinel SigninLogs path."},
        {"label": "SOAR Lab", "href": "/soar", "why": "Automation with a human gate."},
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Write the investigation pack."},
    ],
    "d5": [
        {"label": "Portfolio", "href": "/career/portfolio", "why": "Document residual risk + next."},
        {"label": "Interview Gym", "href": "/career/interview", "why": "Program talk after IR."},
    ],
}


def _wrap(s: str) -> str:
    """Dedent, strip, and clarify exam slang into professor-plain English."""
    return _professor_clarify(textwrap.dedent(s).strip())


def _extract_phrase(body: str, prefix: str) -> str:
    """First line or sentence after a label like Remember: or Common trap:"""
    if not body or prefix not in body:
        return ""
    tail = body.split(prefix, 1)[1].strip()
    if not tail:
        return ""
    line = tail.split("\n", 1)[0].strip()
    if len(line) < 20 and "\n" in tail:
        line = (line + " " + tail.split("\n", 1)[1].split("\n", 1)[0]).strip()
    return line[:480]


def _extract_work_picture(body: str) -> str:
    """Grab the work-facing paragraph after 'Where you see this at work'."""
    marker = "Where you see this at work"
    if marker not in body:
        return ""
    tail = body.split(marker, 1)[1].strip()
    if tail.startswith(":"):
        tail = tail[1:].strip()
    chunk = tail.split("\n\n", 1)[0].strip()
    return " ".join(chunk.split())[:320]


def _term_say_hint(body: str, term: str) -> str:
    """One plain sentence a teacher could say to define term (best-effort from lesson body)."""
    low = body.lower()
    t = term.lower()
    idx = low.find(t)
    if idx >= 0:
        start = max(0, body.rfind("\n", 0, idx))
        end = body.find("\n\n", idx)
        if end == -1:
            end = min(len(body), idx + 220)
        snippet = body[start:end].strip().replace("\n", " ")
        if len(snippet) > 30:
            return snippet[:280]
    return f"Say what {term} means in plain English before you use it in the story."


def synthesize_teach_back(
    *,
    title: str,
    goal: str,
    key_terms: list[str],
    sections: list[dict[str, str]],
) -> dict[str, Any]:
    """Build teach-back block so every Show-me prepares you to explain the lesson to someone else."""
    bodies = "\n\n".join(s.get("body") or "" for s in sections)
    remember = _extract_phrase(bodies, "Remember:")
    trap = _extract_phrase(bodies, "Common trap:")
    work = _extract_work_picture(bodies)
    listener = (
        f'Imagine a teammate says: "I keep missing questions about {title.lower()}. '
        f'Explain it like I am new on the desk."'
    )
    explain_parts: list[str] = []
    if goal:
        explain_parts.append(goal.strip())
    if work:
        explain_parts.append(work)
    if remember:
        explain_parts.append(f"Close with: {remember}")
    explain_aloud = " ".join(explain_parts).strip()
    if len(explain_aloud) < 40:
        explain_aloud = (
            f"This lesson is about {title}. Start with why it matters on the exam and on the desk, "
            f"then walk through one example before you name the trap."
        )
    define_first = [
        {"term": term, "say": _term_say_hint(bodies, term)}
        for term in (key_terms[:3] if key_terms else [])
    ]
    while len(define_first) < 3:
        define_first.append(
            {"term": "Key idea", "say": "Name the one idea the exam keeps retesting in this lesson."}
        )
    desk = work or f"Tie {title.lower()} to one alert, ticket, or log line you would actually show a junior."
    return {
        "listener_prompt": listener,
        "explain_aloud": explain_aloud,
        "define_first": define_first,
        "desk_one_liner": desk[:280],
        "exam_trap": trap or "Name the near-miss wrong answer from this lesson before you pick A or B.",
    }


def _professor_clarify(text: str) -> str:
    """Replace undefined exam slang with plain teaching language.

    Applied at build time so every domain inherits DEFINE-BEFORE-USE cleanup.
    """
    if not text:
        return text
    # Order matters: longer / more specific phrases first.
    swaps = [
        ("Watch out:", "Common trap:"),
        ("Exam trick:", "Common trap:"),
        ("the distractor usually mixes", "the wrong answer that looks close usually mixes"),
        ("the distractor", "the wrong answer that looks close"),
        ("spot the distractor", "spot the wrong answer that looks close"),
        ("Walk the stem like a tutor video", "How to read the question on exam day"),
        ("Walk the stem:", "How to read the question:"),
        ("walk the stem", "read the question"),
        ("what the stem shows", "what the question describes"),
        ("what the stem is testing", "what the question is testing"),
        ("which axis the stem is testing", "which idea the question is testing"),
        ("scenario stems", "exam questions"),
        ("the stem", "the question"),
        ("stem writers", "exam writers"),
        ("SY0-701 loves asking you", "On the Security+ exam, you will often be asked"),
        ("SY0-701 asks you", "The Security+ exam asks you"),
        ("SY0-701 will ask you", "the Security+ exam will ask you"),
        ("That is what SY0-701 will ask", "That is what the Security+ exam will ask"),
        ("on SY0-701 you", "on the Security+ exam you"),
        ("on SY0-701", "on the Security+ exam"),
        ("for SY0-701", "for the Security+ exam"),
        ("Pass objective", "Learn objective"),
        ("straight to SY0-701 scenario stems", "straight to Security+ scenario questions"),
        ("Hook: ", ""),
        ("Analogy: ", "Everyday picture: "),
    ]
    out = text
    for old, new in swaps:
        out = out.replace(old, new)
    out = out.replace("the the Security+ exam", "the Security+ exam")
    out = out.replace("The the Security+ exam", "The Security+ exam")
    return out


def _mc(prompt, choices, idx, hint, explain=None):
    """Help-me item. explain defaults to hint when omitted in compact specs."""
    return {
        "prompt": prompt,
        "choices": list(choices),
        "answer_idx": int(idx),
        "hint": hint,
        "explain": explain if explain is not None else hint,
    }


def _qz(qid, q, choices, idx, explain):
    return {
        "id": qid,
        "q": q,
        "choices": list(choices),
        "answer_idx": int(idx),
        "explain": explain,
    }


LESSON_SPECS: list[dict] = []


# 701 → 801 objective_ref retag (applied at build unless lesson is already 801-native).
LEGACY_TO_801: dict[str, str] = {
    "1.1": "1.1",
    "1.2": "1.1",
    "1.3": "1.2",
    "1.4": "1.3",
    "2.1": "2.2",
    "2.2": "2.3",
    "2.3": "2.4",
    "2.4": "2.5",
    "2.5": "4.1",
    "3.1": "3.1",
    "3.2": "3.2",
    "3.3": "3.3",
    "3.4": "3.4",
    "4.1": "4.1",
    "4.2": "4.2",
    "4.3": "4.3",
    "4.4": "4.4",
    "4.5": "4.1",
    "4.6": "4.5",
    "4.7": "4.6",
    "4.8": "4.7",
    "4.9": "4.8",
    "5.1": "5.1",
    "5.2": "5.2",
    "5.3": "5.3",
    "5.4": "5.4",
    "5.5": "5.5",
    "5.6": "5.6",
}


def add(
    lesson_id,
    domain_id,
    objective_ref,
    title,
    minutes,
    key_terms,
    sections,
    practice,
    quiz,
    pbq=None,
    goal="",
    job_ctas=None,
    objective_exam: str | None = None,
    legacy_ref: str | None = None,
    teach_back: dict[str, Any] | None = None,
):
    """Register one micro-lesson."""
    domain_key = domain_id.split("_")[0]  # d1, d2, ...
    ctas = JOB_CTAS.get(job_ctas or domain_key, JOB_CTAS["d1"])

    def _clarify_item(item: dict) -> dict:
        out = dict(item)
        for key in ("hint", "explain", "prompt", "q", "coach", "teach"):
            if key in out and isinstance(out[key], str):
                out[key] = _professor_clarify(out[key])
        if isinstance(out.get("choices"), list):
            out["choices"] = [
                _professor_clarify(c) if isinstance(c, str) else c
                for c in out["choices"]
            ]
        return out

    wrapped_sections = [{"heading": _professor_clarify(h), "body": _wrap(b)} for h, b in sections]
    goal_text = _professor_clarify(goal) if goal else (
        f"Learn objective {objective_ref} for the Security+ exam: know the definition, "
        f"spot the wrong answer that looks close, and apply it under time pressure."
    )
    tb = teach_back or synthesize_teach_back(
        title=title,
        goal=goal_text,
        key_terms=list(key_terms),
        sections=wrapped_sections,
    )
    LESSON_SPECS.append({
        "id": lesson_id,
        "domain_id": domain_id,
        "objective_ref": objective_ref,
        "objective_exam": objective_exam,
        "legacy_ref": legacy_ref,
        "title": title,
        "minutes": minutes,
        "key_terms": list(key_terms),
        "sections": wrapped_sections,
        "practice": [_clarify_item(p) for p in practice],
        "quiz": [_clarify_item(q) for q in quiz],
        "pbq": _clarify_item(pbq) if isinstance(pbq, dict) else pbq,
        "goal": goal_text,
        "job_ctas": ctas,
        "has_pbq": pbq is not None,
        "teach_back": tb,
    })


def apply_801_objective_retag(specs: list[dict]) -> None:
    """Map legacy SY0-701 objective_ref values onto SY0-801 IDs; keep legacy_ref."""
    for spec in specs:
        exam = str(spec.get("objective_exam") or "").strip().upper()
        if exam in ("SY0-801", "801"):
            # Already authored against 801 (e.g. new 2.1 / 2.6).
            spec["objective_exam"] = "SY0-801"
            continue
        old = str(spec.get("objective_ref") or "").strip()
        new = LEGACY_TO_801.get(old, old)
        if not spec.get("legacy_ref"):
            spec["legacy_ref"] = old
        spec["objective_ref"] = new
        spec["objective_exam"] = "SY0-801"


def _rotate_mc(item: dict, salt: int) -> dict:
    """Rotate choices so answer_idx spreads across A–D."""
    out = dict(item)
    choices = list(out.get("choices") or [])
    if len(choices) < 4:
        return out
    idx = int(out.get("answer_idx", 0))
    target = int(salt) % 4
    if idx == target:
        return out
    correct = choices[idx]
    others = [c for i, c in enumerate(choices) if i != idx]
    new_choices: list = [None] * 4
    new_choices[target] = correct
    oi = 0
    for i in range(4):
        if new_choices[i] is None:
            new_choices[i] = others[oi]
            oi += 1
    out["choices"] = new_choices
    out["answer_idx"] = target
    return out


def _load_mcq_parallel_pack() -> dict:
    """Load q_id / practice_id → parallel-form choice rewrites."""
    if not MCQ_PARALLEL_PACK.exists():
        return {}
    import json

    data = json.loads(MCQ_PARALLEL_PACK.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _apply_mcq_parallel(item: dict, item_id: str, pack: dict) -> dict:
    """Overlay parallel-form choices from pack; preserve answer_idx meaning."""
    out = dict(item)
    entry = pack.get(item_id)
    if not entry:
        return out
    choices = entry.get("choices")
    if not isinstance(choices, list) or len(choices) != 4:
        return out
    idx = int(entry.get("answer_idx", out.get("answer_idx", 0)))
    if not (0 <= idx < 4):
        idx = int(out.get("answer_idx", 0))
    out["choices"] = [str(c) for c in choices]
    out["answer_idx"] = idx
    return out


def main() -> None:
    """Assemble curriculum modules from domain specs."""
    import gen_secplus_d1 as d1
    import gen_secplus_d2b as d2
    import gen_secplus_d3 as d3
    import gen_secplus_d4 as d4
    import gen_secplus_d5 as d5

    d1.d1_specs(add, _mc, _qz)
    d2.d2_specs(add, _mc, _qz)
    d3.d3_specs(add, _mc, _qz)
    d4.d4_specs(add, _mc, _qz)
    d5.d5_specs(add, _mc, _qz)

    apply_801_objective_retag(LESSON_SPECS)

    for i, spec in enumerate(LESSON_SPECS, start=1):
        spec["order"] = i

    pack = _load_mcq_parallel_pack()
    if pack:
        print(f"MCQ parallel pack entries: {len(pack)}")

    lessons = []
    practice: dict = {}
    quizzes: dict = {}
    pbqs: dict = {}
    global_q = 0
    pack_hits = 0

    for spec in LESSON_SPECS:
        lid = spec["id"]
        domain = next(d for d in DOMAINS if d["id"] == spec["domain_id"])
        lessons.append({
            "id": lid,
            "order": spec["order"],
            "domain_id": spec["domain_id"],
            "domain_order": domain["order"],
            "domain_title": domain["title"],
            "domain_color": domain["color"],
            "domain_weight": domain["weight"],
            "objective_ref": spec["objective_ref"],
            "legacy_ref": spec.get("legacy_ref"),
            "objective_exam": spec.get("objective_exam") or "SY0-801",
            "title": spec["title"],
            "minutes": spec["minutes"],
            "goal": spec["goal"],
            "key_terms": spec["key_terms"],
            "sections": spec["sections"],
            "job_ctas": spec["job_ctas"],
            "has_pbq": spec["has_pbq"],
            "teach_back": spec["teach_back"],
        })
        pitems = []
        for pi, p in enumerate(spec["practice"]):
            item = dict(p)
            item["id"] = f"{lid}_p{pi + 1}"
            if item["id"] in pack:
                pack_hits += 1
            item = _apply_mcq_parallel(item, item["id"], pack)
            pitems.append(_rotate_mc(item, pi + spec["order"]))
        practice[lid] = pitems
        qbank = []
        for qi, q in enumerate(spec["quiz"]):
            global_q += 1
            item = dict(q)
            qid = item.get("id", "")
            if qid in pack:
                pack_hits += 1
            item = _apply_mcq_parallel(item, qid, pack)
            qbank.append(_rotate_mc(item, global_q))
        quizzes[lid] = qbank
        if spec["pbq"]:
            pbqs[lid] = spec["pbq"]

    by_dom: dict[str, int] = {}
    for L in lessons:
        by_dom[L["domain_id"]] = by_dom.get(L["domain_id"], 0) + 1
    print("Lesson counts:", by_dom, "total", len(lessons))
    print("PBQ count:", len(pbqs))
    print(f"MCQ parallel pack applied: {pack_hits}")
    assert 50 <= len(lessons) <= 65, len(lessons)
    assert 12 <= len(pbqs) <= 15, len(pbqs)

    # Hard-fail on severe correct-longest length bias (Option C lint).
    lint_mcq_banks(practice, quizzes, hard_fail=True)

    out_lessons = ROOT / "secplus_lessons.py"
    pp = pprint.PrettyPrinter(width=100, sort_dicts=False)
    body = [
        '"""',
        "Security+ SY0-801 Phase 1 micro-lesson content (generated).",
        "Original Boundry lessons/questions only. Official objective IDs as outline.",
        "objective_ref uses SY0-801 IDs; legacy_ref keeps SY0-701 where remapped.",
        "Regenerate: python tools/build_secplus_phase1.py",
        '"""',
        "from __future__ import annotations",
        "from typing import Any",
        "",
        f"DOMAINS: list[dict[str, Any]] = {pp.pformat(DOMAINS)}",
        "",
        f"LESSONS: list[dict[str, Any]] = {pp.pformat(lessons)}",
        "",
        f"PRACTICE: dict[str, list[dict[str, Any]]] = {pp.pformat(practice)}",
        "",
        f"QUIZZES: dict[str, list[dict[str, Any]]] = {pp.pformat(quizzes)}",
        "",
        f"PBQS: dict[str, dict[str, Any]] = {pp.pformat(pbqs)}",
        "",
    ]
    out_lessons.write_text("\n".join(body), encoding="utf-8")
    print("Wrote", out_lessons, "bytes", out_lessons.stat().st_size)

    engine = ROOT / "secplus_learn.py"
    engine.write_text(ENGINE_SRC, encoding="utf-8")
    print("Wrote", engine)


ENGINE_SRC = r'''"""
Security+ SY0-801 Lab - Phase 1 personal tutor (micro-lessons).

Show me → Help me → Watch me (optional PBQ) → Prove it (≥70%).
Pattern mirrors KQL Learn (ordered lessons, per-lesson practice + quiz).
Original Boundry content only. Official objective IDs as outline, never dumps.
"""

from __future__ import annotations

from typing import Any

from secplus_lessons import DOMAINS, LESSONS, PRACTICE, QUIZZES, PBQS

TRACK_ID = "secplus"
TRACK_TITLE = "Security+ SY0-801 Lab"
TRACK_BLURB = (
    "Your Security+ tutor for CompTIA SY0-801 (801 north star; 701 transition retained). "
    "Bite-sized lessons in exam order D1→D5: show-me depth, Help me, then Prove it (≥70%). "
    "Show me → Help me → Watch me (PBQs) → Prove it. Original Boundry practice only "
    "(official objectives as the outline, never dumps). Domain 4 ties to Shift/SPL/KQL/SOAR."
)

PASS_PCT = 70
CHOICE_LETTERS = "ABCD"


def domain_ids() -> list[str]:
    """Ordered domain ids."""
    return [d["id"] for d in DOMAINS]


def get_domain(domain_id: str) -> dict[str, Any] | None:
    """Return domain metadata by id."""
    for d in DOMAINS:
        if d["id"] == domain_id:
            return d
    return None


def lesson_ids() -> list[str]:
    """Ordered lesson ids (D1→D5 spine)."""
    return [L["id"] for L in LESSONS]


def get_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return one micro-lesson by id."""
    for L in LESSONS:
        if L["id"] == lesson_id:
            return L
    return None


def lessons_for_domain(domain_id: str) -> list[dict[str, Any]]:
    """Lessons belonging to a domain, in spine order."""
    return [L for L in LESSONS if L["domain_id"] == domain_id]


def get_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Help-me checks for a lesson."""
    return PRACTICE.get(lesson_id, [])


def get_pbq(lesson_id: str) -> dict[str, Any] | None:
    """Watch-me PBQ if this lesson is tagged; else None."""
    return PBQS.get(lesson_id)


def get_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Prove-it bank for one lesson (includes answers)."""
    return QUIZZES.get(lesson_id, [])


def _choices_as_letters(choices: list[str]) -> dict[str, str]:
    """Map A–D to choice text."""
    return {CHOICE_LETTERS[i]: text for i, text in enumerate(choices[:4])}


def _letter_to_idx(letter: str) -> int | None:
    """A–D → 0–3."""
    key = (letter or "").strip().upper()
    if len(key) != 1 or key not in CHOICE_LETTERS:
        return None
    return CHOICE_LETTERS.index(key)


def public_practice(lesson_id: str) -> list[dict[str, Any]]:
    """Help-me items without answer_idx (client-safe)."""
    out = []
    for p in get_practice(lesson_id):
        out.append({
            "id": p["id"],
            "prompt": p["prompt"],
            "choices": _choices_as_letters(p["choices"]),
            "hint": p.get("hint") or "",
        })
    return out


def public_pbq(lesson_id: str) -> dict[str, Any] | None:
    """PBQ without answers (client-safe)."""
    pbq = get_pbq(lesson_id)
    if not pbq:
        return None
    kind = pbq["kind"]
    base = {
        "id": pbq["id"],
        "kind": kind,
        "title": pbq["title"],
        "prompt": pbq["prompt"],
    }
    if kind == "pick":
        base["choices"] = [{"id": c["id"], "text": c["text"]} for c in pbq["choices"]]
    elif kind == "order":
        base["steps"] = [{"id": s["id"], "text": s["text"]} for s in pbq["items"]]
    elif kind == "map":
        base["categories"] = list(pbq["categories"])
        # Template expects steps (same shape as order UI rows).
        base["steps"] = [{"id": it["id"], "text": it["text"]} for it in pbq["items"]]
    return base


def public_quiz(lesson_id: str) -> list[dict[str, Any]]:
    """Quiz without answers (client-safe)."""
    return [
        {
            "id": q["id"],
            "q": q["q"],
            "choices": _choices_as_letters(q["choices"]),
        }
        for q in get_quiz(lesson_id)
    ]


def check_practice_answer(lesson_id: str, practice_id: str, picked: str) -> dict[str, Any]:
    """Grade one Help-me check (local, deterministic)."""
    items = get_practice(lesson_id)
    item = next((p for p in items if p["id"] == practice_id), None)
    if not item:
        return {"ok": False, "error": "Unknown practice item"}
    idx = _letter_to_idx(picked)
    correct_idx = int(item["answer_idx"])
    if idx is None:
        return {
            "ok": True,
            "correct": False,
            "verdict": "wrong",
            "explain": "WRONG: pick A-D.",
            "hint": item.get("hint"),
        }
    ok = idx == correct_idx
    return {
        "ok": True,
        "correct": ok,
        "verdict": "correct" if ok else "wrong",
        "explain": item["explain"] if ok else f"WRONG: {item['explain']}",
        "hint": None if ok else item.get("hint"),
        "answer": CHOICE_LETTERS[correct_idx],
    }


def check_pbq_answer(lesson_id: str, payload: dict[str, Any] | None) -> dict[str, Any]:
    """Grade Watch-me PBQ (map / order / pick)."""
    pbq = get_pbq(lesson_id)
    if not pbq:
        return {"ok": False, "error": "Unknown PBQ"}
    data = payload or {}
    kind = pbq["kind"]

    if kind == "pick":
        picked = str(data.get("picked") or "").strip()
        ok = picked == pbq["answer"]
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else f"WRONG: {pbq['explain']}",
            "answer": pbq["answer"],
        }

    if kind == "order":
        user_order = data.get("order") or []
        if not isinstance(user_order, list):
            user_order = []
        user_order = [str(x) for x in user_order]
        want = list(pbq["correct_order"])
        ok = user_order == want
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else (
                "WRONG order. Wanted: " + " → ".join(want) + ". " + str(pbq["explain"])
            ),
            "answer": want,
        }

    if kind == "map":
        mapping = data.get("mapping") or {}
        if not isinstance(mapping, dict):
            mapping = {}
        expected = {it["id"]: it["answer"] for it in pbq["items"]}
        misses = [iid for iid, want in expected.items() if str(mapping.get(iid) or "").strip() != want]
        ok = not misses
        return {
            "ok": True,
            "correct": ok,
            "verdict": "correct" if ok else "wrong",
            "explain": pbq["explain"] if ok else f"WRONG: {len(misses)} mapping(s) off. {pbq['explain']}",
            "answer": expected,
            "misses": misses,
        }

    return {"ok": False, "error": f"Unsupported PBQ kind: {kind}"}


def grade_quiz(lesson_id: str, answers: dict[str, str]) -> dict[str, Any]:
    """Grade prove-it submission {question_id: letter}."""
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
        want_idx = int(q["answer_idx"])
        want = CHOICE_LETTERS[want_idx]
        ok = picked == want
        if ok:
            correct_n += 1
        graded.append({
            "id": q["id"],
            "correct": ok,
            "picked": picked,
            "answer": want,
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
        "passed": pct >= PASS_PCT,
        "graded": graded,
    }


def next_incomplete_lesson(passed_lesson_ids: set[str] | list[str] | None) -> dict[str, Any] | None:
    """First lesson on D1→D5 spine without a Prove pass (Continue pointer)."""
    done = set(passed_lesson_ids or [])
    for L in LESSONS:
        if L["id"] not in done:
            return L
    return None


def domain_lessons_passed(domain_id: str, passed_lesson_ids: set[str] | list[str] | None) -> tuple[int, int]:
    """(passed_count, total) for one domain's micro-lessons."""
    done = set(passed_lesson_ids or [])
    ids = [L["id"] for L in lessons_for_domain(domain_id)]
    return len([i for i in ids if i in done]), len(ids)


def domains_fully_passed(passed_lesson_ids: set[str] | list[str] | None) -> list[str]:
    """Domain ids where every micro-lesson has Prove pass."""
    done = set(passed_lesson_ids or [])
    green = []
    for d in DOMAINS:
        ids = [L["id"] for L in lessons_for_domain(d["id"])]
        if ids and all(i in done for i in ids):
            green.append(d["id"])
    return green


def weakest_lesson(passed_lesson_ids: set[str] | list[str] | None) -> str | None:
    """Lesson id for Saturday CTA / Continue (first incomplete)."""
    nxt = next_incomplete_lesson(passed_lesson_ids)
    return nxt["id"] if nxt else None


def weakest_domain(passed_domain_ids: set[str] | list[str] | None = None,
                   passed_lesson_ids: set[str] | list[str] | None = None) -> str | None:
    """
    First unfinished domain in exam order.
    Prefer lesson-level progress when provided.
    """
    if passed_lesson_ids is not None:
        green = set(domains_fully_passed(passed_lesson_ids))
        for d in DOMAINS:
            if d["id"] not in green:
                return d["id"]
        return None
    done = set(passed_domain_ids or [])
    for d in DOMAINS:
        if d["id"] not in done:
            return d["id"]
    return None


def all_key_terms() -> list[dict[str, Any]]:
    """Curated term bank: unique key_terms with first lesson reference."""
    seen: dict[str, dict[str, Any]] = {}
    for L in LESSONS:
        for term in L.get("key_terms") or []:
            key = term.strip()
            if not key or key.lower() in {k.lower() for k in seen}:
                continue
            seen[key] = {
                "term": key,
                "lesson_id": L["id"],
                "lesson_title": L["title"],
                "domain_id": L["domain_id"],
                "objective_ref": L["objective_ref"],
            }
    return list(seen.values())


def quiz_answer_indices(lesson_id: str) -> list[int]:
    """answer_idx list for smoke tests."""
    return [int(q["answer_idx"]) for q in get_quiz(lesson_id)]


def must_cover_objectives() -> list[str]:
    """Sorted unique objective_ref codes present in the spine."""
    return sorted({L["objective_ref"] for L in LESSONS})
'''


if __name__ == "__main__":
    main()
