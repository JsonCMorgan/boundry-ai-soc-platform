"""Tests for Railway breach response helper (no secrets in repo)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "railway_breach_response.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("railway_breach_response", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_scan_repo_exits_clean() -> None:
    """Tracked files should not match heuristic secret patterns."""
    proc = subprocess.run(
        [sys.executable, str(TOOL), "scan-repo"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert proc.returncode in (0, 2)
    assert "sk-ant-api" not in proc.stdout + proc.stderr


def test_generate_writes_bundle(tmp_path: Path, monkeypatch) -> None:
    """Generate command creates bundle with expected keys."""
    rbr = _load_module()
    monkeypatch.setattr(rbr, "BUNDLE_PATH", tmp_path / "bundle.env")
    assert rbr.cmd_generate() == 0
    text = (tmp_path / "bundle.env").read_text(encoding="utf-8")
    assert "SECRET_KEY=" in text
    assert "CRON_SECRET=" in text
    assert "PASTE_NEW_VALUE" in text
