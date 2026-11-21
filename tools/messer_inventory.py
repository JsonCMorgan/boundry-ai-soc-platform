#!/usr/bin/env python3
"""Walk Messer content root and write manifest.json (no copyrighted body text)."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_paths import messer_root, messer_work_dir  # noqa: E402

VIDEO_EXT = {".mp4", ".mkv", ".mov", ".webm"}
AUDIO_EXT = {".mp3", ".m4a", ".wav"}
DOC_EXT = {".pdf", ".txt", ".md"}
SIDEcar_EXT = {".srt", ".vtt"}
ARCHIVE_EXT = {".zip"}


def _detect_version(names: list[str]) -> str:
    blob = " ".join(names).lower()
    if "sy0-801" in blob or "801" in blob and "sy0" in blob:
        return "SY0-801"
    if "sy0-701" in blob or "701" in blob:
        return "SY0-701"
    return "unknown"


def _rel(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base)).replace("\\", "/")
    except ValueError:
        return str(path)


def build_manifest() -> dict:
    base = messer_root()
    files: list[dict] = []
    if not base.is_dir():
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "root": str(base),
            "error": "root_missing",
            "files": [],
        }
    names: list[str] = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        kind = "other"
        if ext in VIDEO_EXT:
            kind = "video"
        elif ext in AUDIO_EXT:
            kind = "audio"
        elif ext == ".pdf":
            kind = "pdf"
        elif ext in DOC_EXT:
            kind = "document"
        elif ext in SIDEcar_EXT:
            kind = "subtitle"
        elif ext in ARCHIVE_EXT:
            kind = "archive"
        session_hint = None
        m = re.search(r"sy0-\d{3}-(\d{2})(\d{2})-\d{2}", p.name.lower())
        if m:
            session_hint = f"{m.group(1)}.{m.group(2)}"
        names.append(p.name)
        files.append({
            "rel_path": _rel(p, base),
            "name": p.name,
            "ext": ext,
            "kind": kind,
            "bytes": p.stat().st_size,
            "session_hint": session_hint,
        })
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(base),
        "detected_version": _detect_version(names),
        "file_count": len(files),
        "kinds": {},
        "files": files,
    }
    for f in files:
        manifest["kinds"][f["kind"]] = manifest["kinds"].get(f["kind"], 0) + 1
    return manifest


def main() -> int:
    manifest = build_manifest()
    out_dir = messer_work_dir()
    out_path = out_dir / "manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Wrote {out_path} ({manifest.get('file_count', 0)} files, version={manifest.get('detected_version')})")
    print(f"Root: {manifest.get('root')}")
    return 0 if manifest.get("file_count") else 1


if __name__ == "__main__":
    raise SystemExit(main())
