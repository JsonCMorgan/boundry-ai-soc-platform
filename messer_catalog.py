"""Session map: Messer assets ↔ Boundry lessons ↔ objectives."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from messer_paths import messer_work_dir

SESSION_MAP_NAME = "session_map.json"


def session_map_path() -> Path:
    return messer_work_dir() / SESSION_MAP_NAME


def load_session_map() -> list[dict[str, Any]]:
    p = session_map_path()
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data.get("sessions") or []


def save_session_map(sessions: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> Path:
    p = session_map_path()
    payload = {"sessions": sessions, **(meta or {})}
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def companion_for_lesson(lesson_id: str) -> dict[str, Any] | None:
    """Return first session row linked to a Boundry lesson."""
    for row in load_session_map():
        ids = row.get("boundry_lesson_ids") or []
        if lesson_id in ids:
            return row
    return None


def _domain_from_messer_block(block: str) -> str:
    """0102 → d1, 0203 → d2, etc."""
    dom = block[:2]
    mapping = {"01": "d1_concepts", "02": "d2_threats", "03": "d3_architecture", "04": "d4_ops", "05": "d5_program"}
    return mapping.get(dom, "d1_concepts")


def objective_ref_from_messer_block(block: str) -> str:
    """Map sy0-701-BBBB filename block to CompTIA objective id (e.g. 1.2)."""
    dom = int(block[:2])
    sub = int(block[2:4])
    if dom == 0:
        # Messer 0001-xx intro sits before 0101-01; align Help-me/Prove banks to 1.1.
        return "1.1"
    return f"{dom}.{sub}"


def build_session_map_from_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Heuristic v1 map from audio/video filenames + PDF names."""
    import secplus_learn

    lessons_by_obj: dict[str, list[str]] = {}
    for L in secplus_learn.LESSONS:
        ref = L.get("objective_ref") or ""
        lessons_by_obj.setdefault(ref, []).append(L["id"])

    sessions: dict[str, dict[str, Any]] = {}
    root = manifest.get("root") or ""
    for f in manifest.get("files") or []:
        name = f.get("name") or ""
        rel = f.get("rel_path") or ""
        hint = f.get("session_hint")
        m = re.search(r"sy0-\d{3}-(\d{4})-(\d{2})", name.lower())
        if not m:
            continue
        key = f"{m.group(1)}-{m.group(2)}"
        block = m.group(1)
        obj = objective_ref_from_messer_block(block)
        row = sessions.setdefault(key, {
            "messer_session": key,
            "messer_title": re.sub(r"[-_]+", " ", name.rsplit(".", 1)[0]),
            "objective_ref": obj,
            "domain_id": _domain_from_messer_block(block),
            "boundry_lesson_ids": lessons_by_obj.get(obj, [])[:2],
            "audio_paths": [],
            "video_paths": [],
            "notes_pdf": "",
            "transcript_path": "",
        })
        kind = f.get("kind")
        if kind == "audio":
            row["audio_paths"].append(rel)
        elif kind == "video":
            row["video_paths"].append(rel)

    for f in manifest.get("files") or []:
        if f.get("kind") != "pdf":
            continue
        name = (f.get("name") or "").lower()
        if "course-notes" in name:
            for row in sessions.values():
                if not row.get("notes_pdf"):
                    row["notes_pdf"] = f.get("rel_path") or ""

    return sorted(sessions.values(), key=lambda r: r["messer_session"])
