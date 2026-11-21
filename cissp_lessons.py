"""
CISSP Lesson → Quiz routing (Hybrid).

Topic tiers:
  drill  — short definition / single-principle recall → normal quiz
  lesson — process, judgment, multi-step, exam traps → mini-lesson then quiz

Adaptive gate: domain accuracy below ACCURACY_LESSON_THRESHOLD also forces
Lesson → Quiz (even for drill topics) so weak areas get teaching first.
"""

from __future__ import annotations

from typing import Any
import random

# Below this domain accuracy (0–100), always teach first.
ACCURACY_LESSON_THRESHOLD = 70

# Per-domain topic catalogue with tiers.
# Topics should align with CISSP_DOMAINS key_topics where possible.
CISSP_TOPIC_TIERS: dict[int, list[dict[str, str]]] = {
    1: [
        {"topic": "CIA Triad", "tier": "drill",
         "why": "Core definitions — confidentiality, integrity, availability."},
        {"topic": "Ethics (ISC2 Code)", "tier": "drill",
         "why": "Code of ethics canons — primarily recall."},
        {"topic": "Security Policies vs Standards vs Procedures", "tier": "drill",
         "why": "Hierarchy of governance documents — definitional."},
        {"topic": "Risk Management (identify → assess → treat)", "tier": "lesson",
         "why": "Process order and treatment options are classic exam traps."},
        {"topic": "BCP / DRP Planning", "tier": "lesson",
         "why": "BIA → strategy → plan → test; priority and sequence matter."},
        {"topic": "Compliance & Legal / Privacy", "tier": "lesson",
         "why": "Jurisdiction, due care/due diligence, breach notification judgment."},
        {"topic": "Threat Modelling", "tier": "lesson",
         "why": "Method choice and when to apply it in governance context."},
        {"topic": "Security Governance", "tier": "lesson",
         "why": "Roles of board, CISO, and management — priority decisions."},
    ],
    2: [
        {"topic": "Data Roles (Owner, Custodian, User)", "tier": "drill",
         "why": "Clear role definitions — high-frequency recall."},
        {"topic": "Data Classification levels", "tier": "drill",
         "why": "Label meanings and handling basics."},
        {"topic": "Asset Lifecycle", "tier": "lesson",
         "why": "Acquire → use → maintain → dispose; when controls apply."},
        {"topic": "Data Retention & Destruction", "tier": "lesson",
         "why": "Legal hold vs retention vs secure disposal tradeoffs."},
        {"topic": "DLP / DRM / CASB", "tier": "lesson",
         "why": "Choosing the right control for data-in-motion/use/rest."},
        {"topic": "Privacy vs Security", "tier": "lesson",
         "why": "Exam loves conflicts between privacy requirements and security."},
    ],
    3: [
        {"topic": "Secure Design Principles (least privilege, defence in depth)", "tier": "drill",
         "why": "Named principles — usually direct application."},
        {"topic": "Cryptography basics (symmetric vs asymmetric, hashing)", "tier": "drill",
         "why": "Tool selection by use-case — teachable in short form too, but often drill."},
        {"topic": "Security Models (Bell-LaPadula, Biba, Clark-Wilson)", "tier": "lesson",
         "why": "Which model for confidentiality vs integrity — easy to mix up."},
        {"topic": "Zero Trust Architecture", "tier": "lesson",
         "why": "Architecture decisions and trust boundaries."},
        {"topic": "PKI & Certificate Trust", "tier": "lesson",
         "why": "Chain of trust, revocation, and operational pitfalls."},
        {"topic": "Physical Security & Site Design", "tier": "lesson",
         "why": "Layered physical controls and first/best actions."},
        {"topic": "Virtualisation & Cloud Shared Responsibility", "tier": "lesson",
         "why": "Who owns which control in IaaS/PaaS/SaaS."},
    ],
    4: [
        {"topic": "OSI / TCP-IP layer mapping", "tier": "drill",
         "why": "Layer recall and where controls sit."},
        {"topic": "Secure Protocols (TLS, SSH, HTTPS, IPsec)", "tier": "drill",
         "why": "Protocol purpose matching."},
        {"topic": "Firewalls & IDS/IPS placement", "tier": "lesson",
         "why": "Architecture placement and detection vs prevention."},
        {"topic": "VPNs & Tunnelling", "tier": "lesson",
         "why": "Remote access design and when to prefer which VPN type."},
        {"topic": "Wireless Security", "tier": "lesson",
         "why": "WPA2/3, evil twin, and enterprise vs personal modes."},
        {"topic": "Network Attacks & Microsegmentation", "tier": "lesson",
         "why": "Attack patterns and segmentation as control strategy."},
    ],
    5: [
        {"topic": "Authentication Factors", "tier": "drill",
         "why": "Something you know/have/are — definitional."},
        {"topic": "MFA & SSO concepts", "tier": "drill",
         "why": "What MFA/SSO provide — often recall."},
        {"topic": "RBAC / ABAC / MAC / DAC", "tier": "lesson",
         "why": "Model selection for a scenario — frequent mix-ups."},
        {"topic": "Kerberos / SAML / OAuth / OIDC", "tier": "lesson",
         "why": "Federation flows and which protocol fits which use-case."},
        {"topic": "Privileged Access Management", "tier": "lesson",
         "why": "Just-in-time, vaulting, and break-glass governance."},
        {"topic": "Zero Trust IAM", "tier": "lesson",
         "why": "Continuous verification and least standing privilege."},
    ],
    6: [
        {"topic": "Vulnerability Scanning vs Pen Testing", "tier": "drill",
         "why": "Purpose difference — classic definition pair."},
        {"topic": "Red vs Blue vs Purple Teams", "tier": "drill",
         "why": "Role definitions."},
        {"topic": "Security Audits & Evidence", "tier": "lesson",
         "why": "Independence, sampling, and management response."},
        {"topic": "Log Analysis & SIEM Testing", "tier": "lesson",
         "why": "What to test and how to validate detection."},
        {"topic": "BCP / DRP Testing types", "tier": "lesson",
         "why": "Tabletop → simulation → full interrupt — order and purpose."},
        {"topic": "Continuous Monitoring strategy", "tier": "lesson",
         "why": "Risk-based monitoring decisions."},
    ],
    7: [
        {"topic": "Logging & Monitoring basics", "tier": "drill",
         "why": "What to log — foundational recall."},
        {"topic": "Incident Response lifecycle", "tier": "lesson",
         "why": "Preparation → Detection → Containment → Eradication → Recovery → Lessons — FIRST/BEST order."},
        {"topic": "SIEM & SOC Operations", "tier": "lesson",
         "why": "Triage priority and escalation judgment."},
        {"topic": "Digital Forensics & Chain of Custody", "tier": "lesson",
         "why": "Evidence handling order and legal traps."},
        {"topic": "Threat Intelligence use", "tier": "lesson",
         "why": "When intel changes detection vs response."},
        {"topic": "BCP / DRP Execution", "tier": "lesson",
         "why": "Declare disaster, RTO/RPO decisions under pressure."},
        {"topic": "eDiscovery", "tier": "lesson",
         "why": "Legal hold vs IR — process conflicts."},
    ],
    8: [
        {"topic": "OWASP Top 10 awareness", "tier": "drill",
         "why": "Named risks — recall with light application."},
        {"topic": "SQL Injection & XSS distinction", "tier": "drill",
         "why": "Attack class identification."},
        {"topic": "SDLC Security Phases", "tier": "lesson",
         "why": "When to inject security activities — shift left."},
        {"topic": "Secure Coding & Code Review", "tier": "lesson",
         "why": "What reviewers must catch vs what scanners catch."},
        {"topic": "DevSecOps gates", "tier": "lesson",
         "why": "Pipeline controls and release decisions."},
        {"topic": "API Security", "tier": "lesson",
         "why": "AuthZ, rate limits, and object-level access."},
        {"topic": "Threat Modelling in SDLC", "tier": "lesson",
         "why": "When and how deeply to model threats."},
    ],
}


def get_topic_catalog(domain_num: int) -> list[dict[str, str]]:
    """Return topic tier list for a domain (empty if unknown)."""
    return list(CISSP_TOPIC_TIERS.get(domain_num, []))


def domain_accuracy_pct(attempts: int, correct: int) -> float | None:
    """Accuracy 0–100, or None if no attempts yet."""
    if not attempts:
        return None
    return round(100.0 * correct / attempts, 1)


def pick_topic(domain_num: int, accuracy: float | None = None) -> dict[str, str]:
    """
    Pick a topic for the next item.
    Weak / unseen domains bias toward lesson-tier topics;
    strong domains bias toward drill-tier (faster reps).
    """
    catalog = get_topic_catalog(domain_num)
    if not catalog:
        return {"topic": "Core concepts", "tier": "lesson", "why": "Domain overview"}

    lesson_topics = [t for t in catalog if t["tier"] == "lesson"]
    drill_topics = [t for t in catalog if t["tier"] == "drill"]

    weak = accuracy is None or accuracy < ACCURACY_LESSON_THRESHOLD
    if weak:
        pool = lesson_topics * 3 + drill_topics  # ~75% lesson bias
    else:
        pool = drill_topics * 3 + lesson_topics  # ~75% drill bias
    if not pool:
        pool = catalog
    return dict(random.choice(pool))


def decide_path(
    topic: dict[str, str],
    accuracy: float | None,
    mode: str = "auto",
) -> dict[str, Any]:
    """
    Decide lesson vs drill path.

    mode:
      auto         — hybrid (tier + accuracy)
      force_lesson — always lesson → quiz
      force_drill  — always normal quiz
    """
    mode = (mode or "auto").strip().lower()
    if mode not in ("auto", "force_lesson", "force_drill"):
        mode = "auto"

    tier = topic.get("tier") or "lesson"
    weak = accuracy is None or accuracy < ACCURACY_LESSON_THRESHOLD

    if mode == "force_lesson":
        use_lesson = True
        reason = "You chose Lesson → Quiz mode."
    elif mode == "force_drill":
        use_lesson = False
        reason = "You chose Quiz-only mode."
    elif tier == "lesson":
        use_lesson = True
        reason = f"Topic tier is Lesson — {topic.get('why') or 'needs teaching first.'}"
    elif weak:
        use_lesson = True
        if accuracy is None:
            reason = (
                f"New/unseen domain — teach first "
                f"(threshold {ACCURACY_LESSON_THRESHOLD}%)."
            )
        else:
            reason = (
                f"Domain accuracy {accuracy:.0f}% is below "
                f"{ACCURACY_LESSON_THRESHOLD}% — teach first."
            )
    else:
        use_lesson = False
        reason = (
            f"Topic tier is Drill and accuracy {accuracy:.0f}% ≥ "
            f"{ACCURACY_LESSON_THRESHOLD}% — quiz only."
        )

    return {
        "path": "lesson" if use_lesson else "drill",
        "mode": mode,
        "topic": topic.get("topic") or "Core concepts",
        "tier": tier,
        "reason": reason,
        "accuracy": accuracy,
        "threshold": ACCURACY_LESSON_THRESHOLD,
        "weak": weak,
    }


def lesson_system_prompt() -> str:
    """System prompt for mini-lesson generation."""
    return (
        "You are an expert ISC2 CISSP instructor. Write ENTIRELY in English. "
        "Teach clearly and concisely for a working SOC analyst studying for CISSP. "
        "Prefer manager mindset: process, priority, governance, risk before tools."
    )


def build_lesson_prompt(domain_num: int, domain_name: str, topic: str, weight: int) -> str:
    """User prompt for a short concept lesson."""
    return f"""Create a SHORT CISSP study lesson for Domain {domain_num}: {domain_name} ({weight}% of exam).
Focus topic: {topic}

Requirements:
1. Teach the concept so the learner can answer a scenario-based CISSP question next.
2. Emphasize CISSP exam thinking: FIRST/BEST action, people→process→technology, risk before controls.
3. Include 1 common exam trap (what wrong answers usually look like).
4. Keep it tight — busy professional length.
5. English only. No markdown fences.

Respond ONLY with valid JSON:
{{"title":"<lesson title>","summary":"<1-2 sentence overview>","body":"<3-5 short paragraphs separated by \\n\\n>","key_takeaways":["<takeaway1>","<takeaway2>","<takeaway3>"],"exam_trap":"<one common wrong-answer trap>","topic":"{topic}"}}"""


def build_lesson_quiz_prompt(
    domain_num: int,
    domain_name: str,
    topic: str,
    lesson: dict[str, Any],
    difficulty_hint: int | None = None,
) -> str:
    """User prompt for a question grounded ONLY in the lesson just taught."""
    takeaways = lesson.get("key_takeaways") or []
    takeaways_str = "; ".join(str(t) for t in takeaways[:5])
    body = (lesson.get("body") or "")[:2800]
    trap = lesson.get("exam_trap") or ""
    title = lesson.get("title") or topic

    diff = ""
    if difficulty_hint == 1:
        diff = "\nDifficulty: BEGINNER — straightforward application of the lesson."
    elif difficulty_hint == 3:
        diff = "\nDifficulty: ADVANCED — ambiguous scenario; all distractors plausible."
    elif difficulty_hint == 2:
        diff = "\nDifficulty: INTERMEDIATE — realistic workplace judgment."

    return f"""You are an expert ISC2 CISSP exam question writer. English only.

The learner JUST studied this lesson for Domain {domain_num}: {domain_name}.
Lesson title: {title}
Topic: {topic}
Lesson body:
{body}

Key takeaways: {takeaways_str}
Exam trap to exploit in distractors: {trap}
{diff}

Write ONE scenario-based question that tests ONLY concepts from this lesson.
Frame as FIRST or BEST action. Exactly 4 options A–D. One best answer.

Respond ONLY with valid JSON — no markdown:
{{"scenario":"<3-5 sentence scenario>","question":"<FIRST or BEST question>","options":{{"A":"<opt>","B":"<opt>","C":"<opt>","D":"<opt>"}},"correct":"<A|B|C|D>","explanation":"<why correct is best AND why others are wrong, tied to the lesson>","mindset":"<manager|technical|both>","difficulty":<1|2|3>,"topic":"{topic}"}}"""
