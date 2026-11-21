"""
Map Boundry Security+ lessons/quizzes against the SY0-801 objective matrix.

Boundry Phase-1 content was authored for SY0-701. This audit maps those
objective_ref tags through a 701→801 crosswalk onto the official SY0-801
matrix (north star for Jason's Nov 2026 attempt).

Reads:  docs/exam-outlines/sy0-801-objectives.json
Writes: docs/secplus-objective-coverage.md

Usage:
  python tools/secplus_coverage_audit.py
  python tools/secplus_coverage_audit.py --json-only

Does not paste CompTIA proprietary quiz text. PDF presence is file-existence only.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secplus_lessons import LESSONS, PBQS, PRACTICE, QUIZZES  # noqa: E402

OBJECTIVES_JSON = ROOT / "docs" / "exam-outlines" / "sy0-801-objectives.json"
PDF_PATH = ROOT / "docs" / "exam-outlines" / "comptia-sy0-801-exam-objectives.pdf"
STATUS_MD = ROOT / "docs" / "secplus-objective-coverage.md"

# Extra keyword / title signals for 801 topics Boundry may touch without a clean ID map.
KEYWORD_HINTS: dict[str, list[str]] = {
    "2.1": ["cvss", "cve", "threat feed", "vulnerability scoring", "prioritization"],
    "2.6": [
        "artificial intelligence",
        " prompt injection",
        "jailbreak",
        "llm",
        "model poison",
        "hallucination",
        "ai usage",
        "generative ai",
    ],
    "4.1": [
        "honeypot",
        "honeyfile",
        "honeytoken",
        "bimi",
        "edr",
        "xdr",
        "dmarc",
        "spf",
        "dkim",
        "mitigat",
        "hardening",
        "deception",
    ],
    "2.5": ["quishing", "deepfake", "qr code", "mfa bypass"],
    "4.3": ["cspm", "bug bounty", "responsible disclosure", "cloud posture"],
    "4.5": ["passkey", "passwordless", "just-in-time", "gmsa"],
    "4.6": ["agentic", "chatbot", "guardrail"],
}


def load_matrix() -> dict[str, Any] | None:
    """Load SY0-801 objective matrix JSON, or None if missing."""
    if not OBJECTIVES_JSON.is_file():
        return None
    return json.loads(OBJECTIVES_JSON.read_text(encoding="utf-8"))


def iter_objectives(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten domains → objectives with domain metadata attached."""
    rows: list[dict[str, Any]] = []
    for domain in matrix.get("domains") or []:
        for obj in domain.get("objectives") or []:
            rows.append(
                {
                    "id": str(obj.get("id") or "").strip(),
                    "title": str(obj.get("title") or "").strip(),
                    "pdf_verified": bool(obj.get("pdf_verified")),
                    "source": str(obj.get("source") or ""),
                    "sub_topic_count": len(obj.get("sub_topics") or []),
                    "domain_id": domain.get("id"),
                    "domain_order": domain.get("order"),
                    "domain_title": domain.get("title"),
                    "weight_percent": domain.get("weight_percent"),
                }
            )
    return rows


def _lesson_blob(lesson: dict[str, Any]) -> str:
    """Lowercase title/goal/terms blob for keyword soft-hits."""
    title = str(lesson.get("title") or "")
    goal = str(lesson.get("goal") or "")
    terms = " ".join(str(t) for t in (lesson.get("key_terms") or []))
    return f" {title} {goal} {terms}".lower()


def boundry_by_701_ref() -> dict[str, dict[str, Any]]:
    """Aggregate Boundry content keyed by legacy_ref when present, else objective_ref.

    Used for orphan detection against the 701→801 crosswalk keys.
    """
    by_obj: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "lessons": [],
            "titles": [],
            "practice_q": 0,
            "quiz_q": 0,
            "pbq_lessons": [],
            "blob": "",
        }
    )
    for lesson in LESSONS:
        legacy = str(lesson.get("legacy_ref") or "").strip()
        exam = str(lesson.get("objective_exam") or "").strip().upper()
        # Pure 801-native lessons (no 701 ancestry) are not crosswalk orphans.
        if exam in ("SY0-801", "801") and not legacy:
            continue
        ref = legacy or str(lesson.get("objective_ref") or "").strip()
        if not ref:
            continue
        lid = lesson["id"]
        title = str(lesson.get("title") or "")
        by_obj[ref]["lessons"].append(lid)
        by_obj[ref]["titles"].append(title)
        by_obj[ref]["practice_q"] += len(PRACTICE.get(lid, []))
        by_obj[ref]["quiz_q"] += len(QUIZZES.get(lid, []))
        if lid in PBQS:
            by_obj[ref]["pbq_lessons"].append(lid)
        by_obj[ref]["blob"] += _lesson_blob(lesson)
    return dict(by_obj)


def map_boundry_to_801(
    cov_701: dict[str, dict[str, Any]],
    crosswalk: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Map Boundry lessons onto 801 IDs.

    Prefer per-lesson mapping:
    - If objective_exam is SY0-801 (or legacy_ref is set), objective_ref is already 801.
    - Else treat objective_ref as a 701 ID and apply the crosswalk.
    """
    del cov_701  # kept in signature for callers; mapping is per-lesson now
    by_801: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "lessons": [],
            "titles": [],
            "practice_q": 0,
            "quiz_q": 0,
            "pbq_lessons": [],
            "via_701_refs": [],
            "map_notes": [],
            "keyword_hits": [],
            "blob": "",
        }
    )

    for lesson in LESSONS:
        ref = str(lesson.get("objective_ref") or "").strip()
        if not ref:
            continue
        lid = lesson["id"]
        title = str(lesson.get("title") or "")
        legacy = str(lesson.get("legacy_ref") or "").strip()
        exam = str(lesson.get("objective_exam") or "").strip().upper()
        is_801_native = exam in ("SY0-801", "801") or bool(legacy)

        if is_801_native:
            targets = [ref]
            via = legacy
            note = "801-native objective_ref" if not legacy else f"retagged from 701 {legacy}"
        else:
            entry = crosswalk.get(ref) or {}
            targets = list(entry.get("maps_to") or []) or [ref]
            via = ref
            note = str(entry.get("note") or entry.get("status") or "")

        prac_n = len(PRACTICE.get(lid, []))
        quiz_n = len(QUIZZES.get(lid, []))
        blob = _lesson_blob(lesson)
        for tid in targets:
            bucket = by_801[tid]
            if lid not in bucket["lessons"]:
                bucket["lessons"].append(lid)
            if title and title not in bucket["titles"]:
                bucket["titles"].append(title)
            bucket["practice_q"] += prac_n
            bucket["quiz_q"] += quiz_n
            if lid in PBQS and lid not in bucket["pbq_lessons"]:
                bucket["pbq_lessons"].append(lid)
            if via and via not in bucket["via_701_refs"]:
                bucket["via_701_refs"].append(via)
            if note and note not in bucket["map_notes"]:
                bucket["map_notes"].append(note)
            bucket["blob"] += " " + blob

    # Keyword soft-hits for 801-native topics (especially NEW objectives)
    global_bits: list[str] = []
    for lesson in LESSONS:
        global_bits.append(_lesson_blob(lesson))
        for sec in lesson.get("sections") or []:
            if isinstance(sec, dict):
                global_bits.append(str(sec.get("heading") or ""))
                global_bits.append(str(sec.get("body") or ""))
    global_blob = " ".join(global_bits).lower()

    for oid, needles in KEYWORD_HINTS.items():
        hits = [n.strip() for n in needles if n.strip() and n.strip() in global_blob]
        if hits:
            by_801[oid]["keyword_hits"] = hits

    return dict(by_801)


def coverage_label(cov: dict[str, Any] | None, *, is_new: bool = False) -> str:
    """Human label for one 801 objective's Boundry footprint."""
    if not cov or not cov.get("lessons"):
        if cov and cov.get("keyword_hits"):
            return "keyword_only"
        return "GAP"
    has_quiz = cov.get("quiz_q", 0) > 0
    has_practice = cov.get("practice_q", 0) > 0
    if has_quiz and has_practice:
        return "covered"
    if has_quiz or has_practice:
        return "partial"
    return "lesson_only"


def migration_tag(
    oid: str,
    cov: dict[str, Any] | None,
    matrix: dict[str, Any],
) -> str:
    """Classify still_valid / changed / new_on_801 / 701_leftover relative to 801."""
    new_ids = set(matrix.get("sy0801_new_objectives") or [])
    if oid in new_ids:
        return "new_on_801"
    cross = matrix.get("crosswalk_from_sy0701") or {}
    # Find 701 refs that map here
    statuses: list[str] = []
    for _ref701, meta in cross.items():
        if oid in (meta.get("maps_to") or []):
            statuses.append(str(meta.get("status") or ""))
    if "moved" in statuses:
        return "changed"
    if "merged" in statuses:
        return "changed"
    if "changed" in statuses:
        return "changed"
    if "renumbered" in statuses:
        return "still_valid"
    if "still_valid" in statuses:
        return "still_valid"
    if cov and cov.get("via_701_refs"):
        return "still_valid"
    return "new_on_801"


def build_report(matrix: dict[str, Any] | None) -> dict[str, Any]:
    """Build structured coverage report for console + markdown."""
    pdf_present = PDF_PATH.is_file()
    cov_701 = boundry_by_701_ref()
    crosswalk = (matrix or {}).get("crosswalk_from_sy0701") or {}
    cov_801 = map_boundry_to_801(cov_701, crosswalk) if matrix else {}
    matrix_objs = iter_objectives(matrix) if matrix else []
    matrix_ids = {r["id"] for r in matrix_objs if r["id"]}
    new_ids = set((matrix or {}).get("sy0801_new_objectives") or [])

    mapped_801_ids = set()
    for meta in crosswalk.values():
        mapped_801_ids.update(meta.get("maps_to") or [])
    orphan_701 = sorted(set(cov_701.keys()) - set(crosswalk.keys()))
    # 701 refs whose map target is not in 801 matrix (shouldn't happen)
    leftover_701_only = sorted(
        ref
        for ref, meta in crosswalk.items()
        if not set(meta.get("maps_to") or []) & matrix_ids
    )

    rows: list[dict[str, Any]] = []
    for meta in matrix_objs:
        oid = meta["id"]
        c = cov_801.get(oid)
        mig = migration_tag(oid, c, matrix or {})
        label = coverage_label(c, is_new=oid in new_ids)
        rows.append(
            {
                **meta,
                "lessons": (c or {}).get("lessons", []),
                "titles": (c or {}).get("titles", []),
                "practice_q": (c or {}).get("practice_q", 0),
                "quiz_q": (c or {}).get("quiz_q", 0),
                "pbq_lessons": (c or {}).get("pbq_lessons", []),
                "via_701_refs": (c or {}).get("via_701_refs", []),
                "map_notes": (c or {}).get("map_notes", []),
                "keyword_hits": (c or {}).get("keyword_hits", []),
                "migration": mig,
                "status": label,
                "is_new_on_801": oid in new_ids,
            }
        )

    counts = defaultdict(int)
    mig_counts = defaultdict(int)
    for r in rows:
        counts[r["status"]] += 1
        mig_counts[r["migration"]] += 1

    covered_n = counts.get("covered", 0)
    partial_n = counts.get("partial", 0) + counts.get("lesson_only", 0) + counts.get(
        "keyword_only", 0
    )
    gap_n = counts.get("GAP", 0)
    total = len(rows) or 1
    # Coverage %: covered fully + half-credit for partial footprints
    coverage_pct = round(
        100.0
        * (
            covered_n
            + 0.5 * counts.get("partial", 0)
            + 0.35 * counts.get("lesson_only", 0)
            + 0.15 * counts.get("keyword_only", 0)
        )
        / total,
        1,
    )
    hard_coverage_pct = round(100.0 * covered_n / total, 1)

    # Priority gaps: NEW first, then GAP with no lessons, then partial on heavy domains
    def gap_priority(r: dict[str, Any]) -> tuple:
        weight = float(r.get("weight_percent") or 0)
        status_rank = {"GAP": 0, "keyword_only": 1, "lesson_only": 2, "partial": 3, "covered": 9}.get(
            r["status"], 5
        )
        new_rank = 0 if r.get("is_new_on_801") else 1
        return (new_rank, status_rank, -weight, r["id"])

    priority_gaps = sorted(
        [r for r in rows if r["status"] != "covered"],
        key=gap_priority,
    )

    verified = sum(1 for r in rows if r.get("pdf_verified"))
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "pdf_present": pdf_present,
        "pdf_path": str(PDF_PATH.relative_to(ROOT)).replace("\\", "/"),
        "matrix_present": matrix is not None,
        "matrix_path": str(OBJECTIVES_JSON.relative_to(ROOT)).replace("\\", "/"),
        "exam_code": (matrix or {}).get("exam_code", "SY0-801"),
        "version_label": (matrix or {}).get("version_label", "n/a"),
        "exam_variant": (matrix or {}).get("exam_variant", ""),
        "pdf_status_field": (matrix or {}).get("pdf_status", "n/a"),
        "objective_count": len(rows),
        "pdf_verified_count": verified,
        "status_counts": dict(counts),
        "migration_counts": dict(mig_counts),
        "coverage_pct": coverage_pct,
        "hard_coverage_pct": hard_coverage_pct,
        "orphan_701_refs": orphan_701,
        "leftover_701_only": leftover_701_only,
        "new_on_801": sorted(new_ids),
        "priority_gaps": [
            {
                "id": r["id"],
                "title": r["title"],
                "status": r["status"],
                "migration": r["migration"],
                "domain_title": r.get("domain_title"),
                "weight_percent": r.get("weight_percent"),
                "via_701_refs": r.get("via_701_refs"),
                "lessons": r.get("lessons"),
            }
            for r in priority_gaps[:15]
        ],
        "rows": rows,
        "lesson_count": len(LESSONS),
        "boundry_701_refs": sorted(cov_701.keys()),
    }


def render_markdown(report: dict[str, Any]) -> str:
    """Render status page markdown."""
    sc = report["status_counts"]
    mc = report["migration_counts"]
    pdf_line = (
        f"**PDF on disk:** yes (`{report['pdf_path']}`)"
        if report["pdf_present"]
        else f"**PDF on disk:** no (drop at `{report['pdf_path']}` — see `docs/exam-outlines/README.md`)"
    )
    matrix_line = (
        f"**Matrix JSON:** yes (`{report['matrix_path']}`), version_label=`{report['version_label']}`"
        if report["matrix_present"]
        else f"**Matrix JSON:** missing (`{report['matrix_path']}`)"
    )

    lines = [
        "# Security+ SY0-801 objective coverage",
        "",
        f"_Generated by `tools/secplus_coverage_audit.py` at {report['generated_at']}_",
        "",
        "## North star",
        "",
        "CompTIA Security+ **SY0-801** (refresh targeted **November 2026**) is Boundry's "
        "curriculum north star. Existing Boundry lessons were built for **SY0-701**; this "
        "report maps them through a 701 to 801 crosswalk. Keep 701 content during transition; "
        "new work should target 801 gaps first.",
        "",
        "## Pipeline status",
        "",
        f"- Exam: CompTIA Security+ (`{report['exam_code']}` {report.get('exam_variant') or ''})".rstrip(),
        f"- {pdf_line}",
        f"- {matrix_line}",
        f"- JSON `pdf_status` field: `{report['pdf_status_field']}`",
        f"- Objectives in matrix: **{report['objective_count']}**",
        f"- PDF-verified objectives: **{report['pdf_verified_count']}** / {report['objective_count']}",
        f"- Boundry lessons: **{report['lesson_count']}** "
        "(objective_ref = SY0-801 IDs; legacy_ref keeps 701 where remapped)",
        f"- Weighted coverage score: **{report['coverage_pct']}%** "
        f"(hard fully-covered: **{report['hard_coverage_pct']}%**)",
        f"- Honest note: {report['hard_coverage_pct']}% hard coverage means every 801 "
        "objective has lesson + practice + quiz. Keep deepening changed topics over time.",
        "",
        "## Coverage summary",
        "",
        "| Status | Count | Meaning |",
        "|--------|------:|---------|",
        f"| covered | {sc.get('covered', 0)} | Mapped lesson + practice + quiz |",
        f"| partial | {sc.get('partial', 0)} | Mapped lesson + practice or quiz (not both) |",
        f"| lesson_only | {sc.get('lesson_only', 0)} | Mapped lesson, no practice/quiz yet |",
        f"| keyword_only | {sc.get('keyword_only', 0)} | Soft keyword hit, no `objective_ref` map |",
        f"| GAP | {sc.get('GAP', 0)} | In 801 matrix, no Boundry lesson mapped |",
        "",
        "## Migration vs SY0-701",
        "",
        "| Tag | Count | Meaning |",
        "|-----|------:|---------|",
        f"| still_valid | {mc.get('still_valid', 0)} | Same idea on 801 (often renumbered) |",
        f"| changed | {mc.get('changed', 0)} | Scope/wording/domain shift; lesson needs refresh |",
        f"| new_on_801 | {mc.get('new_on_801', 0)} | No direct 701 objective (write new content) |",
        "",
        f"**Explicit new 801 objectives:** {', '.join(f'`{x}`' for x in report['new_on_801']) or 'none'}",
        "",
        "## Top priority gaps (missing / thin)",
        "",
        "Ranked: **new_on_801** first, then uncovered / thin coverage, heavier domains first.",
        "",
        "| Priority | Obj / title | Domain | Migration | Status | Via 701 | Lessons |",
        "|---------:|-------------|--------|-----------|--------|---------|---------|",
    ]

    if not report["priority_gaps"]:
        lines.append("| — | _(none — all 801 objectives covered)_ | — | — | — | — | — |")
    for i, g in enumerate(report["priority_gaps"], 1):
        lessons = ", ".join(g["lessons"]) if g["lessons"] else "-"
        via = ", ".join(g.get("via_701_refs") or []) or "-"
        title = (g.get("title") or "")[:52].replace("|", "/")
        lines.append(
            f"| {i} | **{g['id']}** {title} | {g.get('domain_title') or '-'} | "
            f"{g['migration']} | {g['status']} | `{via}` | `{lessons}` |"
        )

    lines.extend(
        [
            "",
            "## Refresh priorities (mapped covered, but heavier / changed on 801)",
            "",
            "These show as `covered` via the 701 crosswalk, yet CompTIA expanded or moved them. "
            "Prioritize depth patches here after writing the true gaps above.",
            "",
            "| Obj | Why refresh | 801-heavier bullets to add |",
            "|-----|-------------|------------------------------|",
            "| `4.1` | Keep deepening stack | WIPS, SELinux; BIMI/honeyfile drills shipped (`sp_d4_16`/`sp_d4_17`) |",
            "| `2.3` | Vectors still expanding on 801 | RCS/CAPTCHA abuse depth, signal-based (NFC/RF/BT) drills |",
            "| `2.4` | Attack surfaces | More public-repo / stale-credential PBQs |",
            "| `2.5` | IOC examples | MFA bypass / LOTL packs; quishing/deepfake drill shipped (`sp_d2_13`) |",
            "| `3.2` | Architecture manage | Privilege-creep / OOB mgmt; gMSA beat lives in `sp_d4_19` IAM drill |",
            "| `4.5` | IAM scenario depth | Passkeys/JIT/gMSA drill shipped (`sp_d4_19`); more emergency-access PBQs |",
            "| `4.6` | Automation + AI | Agentic guardrails drill shipped (`sp_d4_20`); more failure PBQs optional |",
            "| `4.3` | Scenario-based vuln mgmt | CSPM/bounty drill shipped (`sp_d4_18`); more disclosure PBQs optional |",
            "| `1.1` | Merged concepts+controls | Keep Zero Trust / least privilege path tight |",
            "| `5.1` | GRC artifacts reframed | Guidelines/benchmarks/advisories vs policies |",
            "",
            "## Recommended next content actions",
            "",
            "1. Keep `2.1` / `2.6` warm with extra Help-me variants after first exam pass attempts.",
            "2. Option A deeper drills shipped: BIMI/honeyfile (`4.1`), quishing/deepfake (`2.5`), "
            "CSPM/bounty (`4.3`), passkeys/JIT/gMSA (`4.5`), agentic guardrails (`4.6`).",
            "3. Next depth targets if needed: `2.3` RCS/signal-based vectors, `2.4` public-repo "
            "creds, `3.2` privilege-creep / OOB mgmt PBQs, MFA-bypass/LOTL packs.",
            "4. Finish remaining still_valid lessons' in-body SY0-701 → SY0-801 exam-code mentions.",
            "5. Optional: move mitigation lessons (`sp_d2_10`/`sp_d2_11`) visually under Domain 4 hub "
            "grouping while keeping unlock order.",
            "6. Leave solid still_valid lessons in place; prefer depth patches over renumber churn.",
            "",
            "## Per-objective map",
            "",
            "| Obj | Domain | Title | Mig | PDF✓ | Via 701 | Lessons | Prac | Quiz | PBQ | Status |",
            "|-----|--------|-------|-----|:----:|---------|---------|-----:|-----:|----:|--------|",
        ]
    )

    for r in report["rows"]:
        domain = r.get("domain_title") or "-"
        pdf_ok = "yes" if r.get("pdf_verified") else "no"
        lessons = ", ".join(r["lessons"]) if r["lessons"] else "-"
        via = ", ".join(r.get("via_701_refs") or []) or "-"
        pbq = len(r.get("pbq_lessons") or [])
        title = (r.get("title") or "").replace("|", "/")
        lines.append(
            f"| {r['id']} | {domain} | {title} | {r['migration']} | {pdf_ok} | `{via}` | "
            f"`{lessons}` | {r['practice_q']} | {r['quiz_q']} | {pbq} | {r['status']} |"
        )

    if report["orphan_701_refs"]:
        lines.extend(
            [
                "",
                "## Orphan Boundry `objective_ref` values (not in crosswalk)",
                "",
            ]
        )
        for oid in report["orphan_701_refs"]:
            lines.append(f"- `{oid}`")

    if report["leftover_701_only"]:
        lines.extend(
            [
                "",
                "## 701-only leftovers (crosswalk target missing on 801)",
                "",
            ]
        )
        for oid in report["leftover_701_only"]:
            lines.append(f"- `{oid}`")

    lines.extend(
        [
            "",
            "## How to refresh",
            "",
            "```text",
            "python tools/secplus_coverage_audit.py",
            "```",
            "",
            "Official PDF path and drop steps: [`docs/exam-outlines/README.md`](exam-outlines/README.md).",
            "",
            "Original Boundry content only. Official objective IDs as outline. Never dumps.",
            "",
        ]
    )
    return "\n".join(lines)


def print_summary(report: dict[str, Any]) -> None:
    """Short console summary for Jason."""
    sc = report["status_counts"]
    print(f"Sec+ SY0-801 coverage audit @ {report['generated_at']}")
    print(f"  PDF present:     {report['pdf_present']}  ({report['pdf_path']})")
    print(f"  Matrix JSON:     {report['matrix_present']}  ({report['matrix_path']})")
    print(f"  version_label:   {report['version_label']}  variant={report.get('exam_variant')}")
    print(
        f"  objectives:      {report['objective_count']} "
        f"(pdf_verified {report['pdf_verified_count']})"
    )
    print(
        f"  coverage:        {report['coverage_pct']}% weighted  "
        f"({report['hard_coverage_pct']}% fully covered)"
    )
    print(
        f"  status:          covered={sc.get('covered', 0)} "
        f"partial={sc.get('partial', 0)} "
        f"lesson_only={sc.get('lesson_only', 0)} "
        f"keyword_only={sc.get('keyword_only', 0)} "
        f"GAP={sc.get('GAP', 0)}"
    )
    print(f"  new_on_801:      {', '.join(report['new_on_801']) or 'none'}")
    print("  top gaps:")
    for g in report["priority_gaps"][:8]:
        print(
            f"    - {g['id']} [{g['migration']}/{g['status']}] "
            f"{(g.get('title') or '')[:60]}"
        )
    print(f"  wrote:           {STATUS_MD.relative_to(ROOT)}")


def main() -> int:
    """CLI entry: audit coverage and write status markdown."""
    parser = argparse.ArgumentParser(description="Security+ SY0-801 objective coverage audit")
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print report JSON to stdout; still writes the markdown status page",
    )
    args = parser.parse_args()

    matrix = load_matrix()
    if matrix is None:
        print(f"WARN: matrix missing at {OBJECTIVES_JSON}", file=sys.stderr)
        print(
            "      Extract PDF → docs/exam-outlines/sy0-801-objectives.json first.",
            file=sys.stderr,
        )

    if matrix is not None:
        desired = "present" if PDF_PATH.is_file() else "missing"
        if matrix.get("pdf_status") != desired:
            matrix["pdf_status"] = desired
            OBJECTIVES_JSON.write_text(
                json.dumps(matrix, indent=2) + "\n", encoding="utf-8"
            )

    report = build_report(matrix)
    STATUS_MD.parent.mkdir(parents=True, exist_ok=True)
    STATUS_MD.write_text(render_markdown(report), encoding="utf-8")

    if args.json_only:
        slim = {k: v for k, v in report.items() if k != "rows"}
        slim["rows"] = [
            {
                "id": r["id"],
                "status": r["status"],
                "migration": r["migration"],
                "lessons": r["lessons"],
                "practice_q": r["practice_q"],
                "quiz_q": r["quiz_q"],
                "via_701_refs": r.get("via_701_refs"),
                "pdf_verified": r["pdf_verified"],
                "is_new_on_801": r.get("is_new_on_801"),
            }
            for r in report["rows"]
        ]
        print(json.dumps(slim, indent=2))
    else:
        print_summary(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
