"""
Extract CompTIA Security+ SY0-801 exam objectives PDF into JSON matrix.

Requires: pypdf
Usage:
  python tools/extract_sy0801_objectives.py
  python tools/extract_sy0801_objectives.py --pdf path/to/file.pdf

Writes docs/exam-outlines/sy0-801-objectives.json (tracked).
Does not commit the PDF. Temporary extract text is gitignored.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PDF = ROOT / "docs" / "exam-outlines" / "comptia-sy0-801-exam-objectives.pdf"
OUT_JSON = ROOT / "docs" / "exam-outlines" / "sy0-801-objectives.json"
TMP_EXTRACT = ROOT / "docs" / "exam-outlines" / "_sy0801_extract.txt"

DOMAIN_META = {
    1: {
        "title": "General Security Concepts",
        "weight_percent": 16,
        "id": "d1_concepts",
    },
    2: {
        "title": "Threats, Vulnerabilities, and Attacks",
        "weight_percent": 24,
        "id": "d2_threats",
    },
    3: {
        "title": "Security Architecture",
        "weight_percent": 19,
        "id": "d3_architecture",
    },
    4: {
        "title": "Security Operations",
        "weight_percent": 27,
        "id": "d4_operations",
    },
    5: {
        "title": "Security Program Management and Oversight",
        "weight_percent": 14,
        "id": "d5_oversight",
    },
}

# Best-effort 701 → 801 migration map (Boundry curriculum planning).
CROSSWALK_701_TO_801: dict[str, dict] = {
    "1.1": {
        "maps_to": ["1.1"],
        "status": "changed",
        "note": "701 controls objective folded into broader 801 1.1 concepts+controls",
    },
    "1.2": {
        "maps_to": ["1.1"],
        "status": "merged",
        "note": "701 fundamental concepts merged into 801 1.1",
    },
    "1.3": {
        "maps_to": ["1.2"],
        "status": "renumbered",
        "note": "Change management; 801 is scenario-based",
    },
    "1.4": {
        "maps_to": ["1.3"],
        "status": "renumbered",
        "note": "Cryptographic solutions",
    },
    "2.1": {
        "maps_to": ["2.2"],
        "status": "renumbered",
        "note": "Threat actors/motivations; 801 2.1 is new threats/vulns characteristics",
    },
    "2.2": {
        "maps_to": ["2.3"],
        "status": "changed",
        "note": "Vectors expanded (QR, RCS, IoT, OT, signal-based, etc.)",
    },
    "2.3": {
        "maps_to": ["2.4"],
        "status": "changed",
        "note": "Vulns + attack surfaces; adds LLMs, public repos, shadow IT",
    },
    "2.4": {
        "maps_to": ["2.5"],
        "status": "renumbered",
        "note": "Indicators of malicious activity; adds deepfake/quishing",
    },
    "2.5": {
        "maps_to": ["4.1"],
        "status": "moved",
        "note": "Mitigation techniques moved from Domain 2 into Domain 4 ops",
    },
    "3.1": {
        "maps_to": ["3.1"],
        "status": "still_valid",
        "note": "Architecture models; wording mostly stable",
    },
    "3.2": {
        "maps_to": ["3.2"],
        "status": "changed",
        "note": "Manage architecture; adds SSE, gMSA, privilege creep",
    },
    "3.3": {
        "maps_to": ["3.3"],
        "status": "still_valid",
        "note": "Data protection strategies",
    },
    "3.4": {
        "maps_to": ["3.4"],
        "status": "still_valid",
        "note": "Resilience and recovery",
    },
    "4.1": {
        "maps_to": ["4.1"],
        "status": "changed",
        "note": "701 resource techniques vs 801 mitigating controls (also absorbs 701 2.5)",
    },
    "4.2": {
        "maps_to": ["4.2"],
        "status": "still_valid",
        "note": "Asset management",
    },
    "4.3": {
        "maps_to": ["4.3"],
        "status": "changed",
        "note": "Now scenario-based; adds CSPM, bounty, responsible disclosure",
    },
    "4.4": {
        "maps_to": ["4.4"],
        "status": "still_valid",
        "note": "Alerting and monitoring",
    },
    "4.5": {
        "maps_to": ["4.1"],
        "status": "merged",
        "note": "Modify enterprise capabilities largely absorbed into 801 4.1 mitigations",
    },
    "4.6": {
        "maps_to": ["4.5"],
        "status": "renumbered",
        "note": "IAM; adds passkey/passwordless/JIT",
    },
    "4.7": {
        "maps_to": ["4.6"],
        "status": "changed",
        "note": "Automation; adds AI agentic/chatbot capabilities",
    },
    "4.8": {
        "maps_to": ["4.7"],
        "status": "renumbered",
        "note": "Incident response",
    },
    "4.9": {
        "maps_to": ["4.8"],
        "status": "renumbered",
        "note": "Investigation data sources",
    },
    "5.1": {
        "maps_to": ["5.1"],
        "status": "changed",
        "note": "Reframed as GRC artifacts",
    },
    "5.2": {
        "maps_to": ["5.2"],
        "status": "still_valid",
        "note": "Risk management",
    },
    "5.3": {
        "maps_to": ["5.3"],
        "status": "still_valid",
        "note": "Third-party risk",
    },
    "5.4": {
        "maps_to": ["5.4"],
        "status": "still_valid",
        "note": "Compliance",
    },
    "5.5": {
        "maps_to": ["5.5"],
        "status": "still_valid",
        "note": "Audits and assessments",
    },
    "5.6": {
        "maps_to": ["5.6"],
        "status": "changed",
        "note": "Now scenario-based awareness",
    },
}


def extract_pdf_text(pdf: Path) -> str:
    """Extract raw text from PDF with page markers."""
    from pypdf import PdfReader

    reader = PdfReader(str(pdf))
    parts: list[str] = [f"PAGES={len(reader.pages)}"]
    md = reader.metadata
    if md:
        parts.append(f"META_TITLE={md.title}")
        parts.append(f"META_SUBJECT={md.subject}")
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        parts.append(f"\n===== PAGE {i + 1} =====\n")
        parts.append(text)
    return "".join(parts)


def parse_objectives(raw: str) -> dict:
    """Parse PDF extract into domain/objective/sub_topic hierarchy."""
    lines: list[str] = []
    for raw_line in raw.splitlines():
        s = raw_line.strip()
        if not s:
            lines.append("")
            continue
        if s.startswith("===== PAGE"):
            continue
        if s.startswith("PAGES=") or s.startswith("META_"):
            continue
        if s.startswith("CompTIA Security+ SY0-801"):
            continue
        if s.startswith("Exam Objectives Document Version"):
            continue
        if s.startswith("Copyright"):
            continue
        if s.startswith("ACRONYM DEFINITION"):
            break
        if "Hardware and Software List" in s:
            break
        lines.append(s)

    obj_header = re.compile(r"^([1-5]\.\d+)\s+(.+)$")
    domain_header = re.compile(r"^([1-5])\.0\s+(.+)$")
    bullet_re = re.compile(r"^[•♦]\s*(.+)$")

    domains = {
        i: {
            "id": DOMAIN_META[i]["id"],
            "order": i,
            "weight_percent": DOMAIN_META[i]["weight_percent"],
            "title": DOMAIN_META[i]["title"],
            "objectives": [],
        }
        for i in range(1, 6)
    }

    current_obj: dict | None = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue
        dm = domain_header.match(line)
        if dm:
            current_obj = None
            i += 1
            continue
        om = obj_header.match(line)
        if om:
            oid, title = om.group(1), om.group(2).strip()
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt:
                    j += 1
                    continue
                if (
                    obj_header.match(nxt)
                    or domain_header.match(nxt)
                    or bullet_re.match(nxt)
                ):
                    break
                if nxt[0].islower() or (len(nxt) < 80 and not nxt.endswith(".")):
                    title = f"{title} {nxt}".strip()
                    j += 1
                    continue
                if not re.match(r"^[A-Z0-9]", nxt):
                    title = f"{title} {nxt}".strip()
                    j += 1
                    continue
                break
            title = re.sub(r"\s+", " ", title).strip()
            dnum = int(oid.split(".")[0])
            current_obj = {
                "id": oid,
                "title": title,
                "source": "official_pdf",
                "pdf_verified": True,
                "sub_topics": [],
            }
            domains[dnum]["objectives"].append(current_obj)
            i = j
            continue
        bm = bullet_re.match(line)
        if bm and current_obj is not None:
            topic = bm.group(1).strip()
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt:
                    j += 1
                    k = j
                    while k < len(lines) and not lines[k]:
                        k += 1
                    if k < len(lines) and (
                        obj_header.match(lines[k])
                        or domain_header.match(lines[k])
                        or bullet_re.match(lines[k])
                    ):
                        break
                    continue
                if (
                    obj_header.match(nxt)
                    or domain_header.match(nxt)
                    or bullet_re.match(nxt)
                ):
                    break
                topic = f"{topic} {nxt}".strip()
                j += 1
            topic = re.sub(r"\s+", " ", topic).strip()
            if topic and topic not in current_obj["sub_topics"]:
                current_obj["sub_topics"].append(topic)
            i = j
            continue
        i += 1

    return {
        "exam": "CompTIA Security+",
        "exam_code": "SY0-801",
        "exam_variant": "V8",
        "version_label": "2.0",
        "schema_version": 1,
        "source_note": (
            "Extracted from official CompTIA Security+ SY0-801 V8 Exam Objectives PDF "
            "(Document Version 2.0). Outline IDs, titles, and sub-topic bullets for Boundry "
            "coverage mapping only. Never dump CompTIA exam items."
        ),
        "pdf_path": "docs/exam-outlines/comptia-sy0-801-exam-objectives.pdf",
        "pdf_status": "present",
        "north_star": True,
        "passing_score": 750,
        "max_questions": 90,
        "test_length_minutes": 90,
        "domains": [domains[i] for i in range(1, 6)],
        "crosswalk_from_sy0701": CROSSWALK_701_TO_801,
        "sy0801_new_objectives": ["2.1", "2.6"],
        "sy0801_new_notes": {
            "2.1": (
                "NEW framing: characteristics of threats and vulnerabilities "
                "(feeds, CVSS, CVE, prioritization)"
            ),
            "2.6": (
                "NEW: AI usage threats/vulns (prompt injection, poisoning, "
                "jailbreaking, hallucinations, etc.)"
            ),
        },
    }


def main() -> int:
    """CLI: extract PDF → sy0-801-objectives.json."""
    parser = argparse.ArgumentParser(description="Extract SY0-801 objectives PDF to JSON")
    parser.add_argument("--pdf", type=Path, default=DEFAULT_PDF, help="Path to 801 PDF")
    parser.add_argument(
        "--keep-extract",
        action="store_true",
        help="Keep temporary _sy0801_extract.txt (gitignored)",
    )
    args = parser.parse_args()

    if not args.pdf.is_file():
        print(f"ERROR: PDF not found: {args.pdf}", file=sys.stderr)
        return 1

    raw = extract_pdf_text(args.pdf)
    # Confirm exam code in text
    if "SY0-801" not in raw and "SY0–801" not in raw:
        print("WARN: SY0-801 not found in PDF text; check you dropped the right file.", file=sys.stderr)
    TMP_EXTRACT.write_text(raw, encoding="utf-8")
    matrix = parse_objectives(raw)
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(matrix, indent=2) + "\n", encoding="utf-8")
    n_obj = sum(len(d["objectives"]) for d in matrix["domains"])
    n_bullets = sum(len(o["sub_topics"]) for d in matrix["domains"] for o in d["objectives"])
    print(f"wrote {OUT_JSON.relative_to(ROOT)} ({n_obj} objectives, {n_bullets} sub_topics)")
    if not args.keep_extract and TMP_EXTRACT.is_file():
        TMP_EXTRACT.unlink()
        print(f"removed temp extract {TMP_EXTRACT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
