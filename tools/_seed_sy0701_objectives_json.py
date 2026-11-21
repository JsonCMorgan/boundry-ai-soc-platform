"""One-shot helper: seed docs/exam-outlines/sy0-701-objectives.json from DOMAINS."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secplus_lessons import DOMAINS  # noqa: E402


def main() -> int:
    """Write seeded objective matrix (pending official PDF verify)."""
    out: dict = {
        "exam": "CompTIA Security+",
        "exam_code": "SY0-701",
        "version_label": "pending_pdf",
        "schema_version": 1,
        "source_note": (
            "Seeded from Boundry secplus_lessons.DOMAINS objective titles. "
            "Not yet verified against the official CompTIA exam objectives PDF. "
            "After Jason drops docs/exam-outlines/comptia-sy0-701-exam-objectives.pdf, "
            "reconcile titles/IDs and set pdf_verified true per objective."
        ),
        "pdf_path": "docs/exam-outlines/comptia-sy0-701-exam-objectives.pdf",
        "pdf_status": "missing",
        "domains": [],
    }
    for d in DOMAINS:
        objs = []
        for line in d["objectives"]:
            code, _, title = line.partition(" ")
            objs.append(
                {
                    "id": code.strip(),
                    "title": title.strip(),
                    "source": "boundry_domain_seed",
                    "pdf_verified": False,
                    "sub_topics": [],
                }
            )
        out["domains"].append(
            {
                "id": d["id"],
                "order": d["order"],
                "weight_percent": d["weight"],
                "title": d["title"],
                "objectives": objs,
            }
        )

    path = ROOT / "docs" / "exam-outlines" / "sy0-701-objectives.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    n = sum(len(x["objectives"]) for x in out["domains"])
    print(f"wrote {path.relative_to(ROOT)} ({n} objectives, {len(out['domains'])} domains)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
