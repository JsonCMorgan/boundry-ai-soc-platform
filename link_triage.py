"""Boundry wrapper for offline link triage (sibling link-check repo or pip install)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable


def _load_analyze() -> Callable[..., dict[str, Any]]:
    try:
        from link_check.analyze import analyze_link

        return analyze_link
    except ImportError:
        pass
    sibling = Path(__file__).resolve().parent.parent / "link-check" / "src"
    if sibling.is_dir():
        root = str(sibling)
        if root not in sys.path:
            sys.path.insert(0, root)
        from link_check.analyze import analyze_link

        return analyze_link
    raise RuntimeError(
        "link-check package not found. Run: pip install -e C:/Dev/link-check"
    )


def analyze_link(url: str, *, claimed_brand: str = "") -> dict[str, Any]:
    """Analyze URL offline; same behavior as `python -m link_check`."""
    fn = _load_analyze()
    return fn(url, claimed_brand=claimed_brand)