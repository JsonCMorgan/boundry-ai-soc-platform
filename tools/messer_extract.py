#!/usr/bin/env python3
"""Extract PDF text and sidecar subtitles into content/private/messer/extracted/."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_root, messer_work_dir  # noqa: E402


def _extract_pdf(path: Path) -> list[dict]:
    try:
        import fitz  # pymupdf
    except ImportError:
        return [{"page": 0, "text": "", "error": "pymupdf not installed; pip install pymupdf"}]
    doc = fitz.open(path)
    pages = []
    for i in range(len(doc)):
        pages.append({"page": i + 1, "text": doc.load_page(i).get_text("text")})
    doc.close()
    return pages


def _pbq_from_practice_exam_pages(pages: list[dict]) -> dict | None:
    """Fallback: Exam A PBQ A5 firewall scenario from practice-exams PDF text."""
    full = "\n".join(p.get("text") or "" for p in pages)
    m = re.search(
        r"A5\.\s+Configure the following stateful firewall rules:[\s\S]{0,4000}?"
        r"(?=\nA6\.|\n\d+\nPractice Exam A - Answers\nA6\.)",
        full,
    )
    if not m:
        return None
    return {
        "id": "pbq_firewall_config",
        "kind": "pbq",
        "source": "practice_exam_a5",
        "text": m.group(0).strip(),
    }


def _tag_pbq_firewall(text: str, source_name: str = "") -> dict | None:
    name = source_name.lower()
    if "sample firewall" in name or "firewall configuration exercise" in name:
        return {"id": "pbq_firewall_config", "kind": "pbq", "text": text[:12000]}
    if "sample firewall configuration exercise" in text.lower()[:4000]:
        return {"id": "pbq_firewall_config", "kind": "pbq", "text": text[:12000]}
    return None


def main() -> int:
    base = messer_root()
    work = messer_work_dir()
    extracted_dir = work / "extracted"
    transcripts_dir = work / "transcripts"
    manifest_path = work / "manifest.json"
    if not manifest_path.is_file():
        print("Run tools/messer_inventory.py first")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    summary = {"pdfs": 0, "subtitles": 0, "pbq": []}
    practice_exam_pages: list[dict] | None = None
    for f in manifest.get("files") or []:
        rel = f.get("rel_path") or ""
        src = base / rel
        if not src.is_file():
            continue
        ext = src.suffix.lower()
        if ext == ".pdf":
            pages = _extract_pdf(src)
            out = {"source": rel, "pages": pages}
            pbq = _tag_pbq_firewall("\n".join(p.get("text") or "" for p in pages), src.name)
            if pbq:
                summary["pbq"].append(pbq)
                (extracted_dir / "pbq_firewall_config.json").write_text(
                    json.dumps(pbq, indent=2), encoding="utf-8"
                )
            safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", src.stem)[:80]
            (extracted_dir / f"{safe}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
            if "practice" in src.name.lower() and "exam" in src.name.lower():
                practice_exam_pages = pages
            summary["pdfs"] += 1
        elif ext in (".srt", ".vtt"):
            dest = transcripts_dir / (src.stem + ".txt")
            dest.write_text(src.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            summary["subtitles"] += 1
        elif ext == ".txt" and "firewall" in src.name.lower():
            text = src.read_text(encoding="utf-8", errors="replace")
            pbq = {"id": "pbq_firewall_config", "kind": "pbq", "text": text}
            summary["pbq"].append(pbq)
            (extracted_dir / "pbq_firewall_config.json").write_text(
                json.dumps(pbq, indent=2), encoding="utf-8"
            )

    if not summary["pbq"] and practice_exam_pages:
        pbq = _pbq_from_practice_exam_pages(practice_exam_pages)
        if pbq:
            summary["pbq"].append(pbq)
            (extracted_dir / "pbq_firewall_config.json").write_text(
                json.dumps(pbq, indent=2), encoding="utf-8"
            )

    (extracted_dir / "_extract_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
