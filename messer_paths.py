"""Resolve Professor Messer content root (private local mirror or OneDrive)."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
LOCAL_MIRROR = REPO_ROOT / "content" / "private" / "messer"
DEFAULT_ONEDRIVE = Path(
    r"C:\Users\ricka\OneDrive\Documents\Cyber Security Course\Professor Messer Security Plus"
)


def messer_root() -> Path:
    """Local-first: MESSER_CONTENT_ROOT, else content/private/messer (never OneDrive unless opted in)."""
    env = (os.environ.get("MESSER_CONTENT_ROOT") or "").strip()
    if env:
        return Path(env)
    if LOCAL_MIRROR.is_dir():
        try:
            if any(LOCAL_MIRROR.iterdir()):
                return LOCAL_MIRROR
        except OSError:
            pass
    if os.environ.get("MESSER_FALLBACK_ONEDRIVE", "").strip().lower() in ("1", "true", "yes"):
        if DEFAULT_ONEDRIVE.is_dir():
            return DEFAULT_ONEDRIVE
    return LOCAL_MIRROR


def messer_work_dir() -> Path:
    """Writable extracted/manifest dir (always under local mirror)."""
    d = LOCAL_MIRROR
    d.mkdir(parents=True, exist_ok=True)
    for sub in ("extracted", "transcripts", "imports"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    return d
