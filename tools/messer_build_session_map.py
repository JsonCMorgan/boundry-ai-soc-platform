#!/usr/bin/env python3
"""Build session_map.json from manifest.json."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from messer_catalog import build_session_map_from_manifest, save_session_map  # noqa: E402
from messer_paths import messer_work_dir  # noqa: E402


def main() -> int:
    manifest_path = messer_work_dir() / "manifest.json"
    if not manifest_path.is_file():
        print("Run tools/messer_inventory.py first")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sessions = build_session_map_from_manifest(manifest)
    path = save_session_map(sessions, meta={
        "detected_version": manifest.get("detected_version"),
        "root": manifest.get("root"),
    })
    print(f"Wrote {path} ({len(sessions)} sessions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
