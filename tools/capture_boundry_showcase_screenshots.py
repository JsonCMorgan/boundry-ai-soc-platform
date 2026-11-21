#!/usr/bin/env python3
"""Capture Boundry UI screenshots for public/boundry-showcase (Playwright)."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "boundry-showcase" / "images"

# (filename, path, needs_analyst_login)
PAGES: list[tuple[str, str, bool]] = [
    ("control-room.png", "/control-room", True),
    ("siem.png", "/siem", True),
    ("siem-query.png", "/siem/query", True),
    ("soc-floor.png", "/soc", True),
    ("career-hub.png", "/career", True),
    ("interview-gym.png", "/career/interview", True),
    ("secplus-learn.png", "/career/secplus", True),
    ("client-reports.png", "/demo", False),
]

DEFAULT_BASE = os.environ.get("SHOWCASE_BASE_URL", "http://127.0.0.1:5000").rstrip("/")


def ensure_playwright() -> None:
    try:
        import playwright  # noqa: F401
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "playwright", "-q"])
        subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])


def login(page, base: str, username: str, password: str) -> bool:
    page.goto(f"{base}/login", wait_until="networkidle", timeout=60_000)
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"], input[type="submit"]')
    page.wait_for_load_state("networkidle", timeout=30_000)
    return "/login" not in page.url


def capture(base: str, username: str, password: str, only: list[str] | None) -> None:
    from playwright.sync_api import sync_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    pages = PAGES
    if only:
        pages = [p for p in PAGES if p[0] in only or p[1] in only]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1440, "height": 900})
        page = context.new_page()

        logged_in = False
        if username and password:
            logged_in = login(page, base, username, password)
            if not logged_in:
                print("[warn] Analyst login failed; skipping protected pages.")

        for fname, path, needs_login in pages:
            if needs_login and not logged_in:
                print(f"[skip] {fname} (login required)")
                continue
            url = f"{base}{path}"
            try:
                page.goto(url, wait_until="networkidle", timeout=90_000)
                page.wait_for_timeout(800)
                dest = OUT / fname
                page.screenshot(path=str(dest), full_page=False)
                print(f"[ok] {fname} <- {url}")
            except Exception as exc:
                print(f"[fail] {fname}: {exc}")

        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default=DEFAULT_BASE, help="Flask base URL")
    parser.add_argument("--only", nargs="*", help="Limit to filenames or paths")
    parser.add_argument("--user", default=os.environ.get("SHOWCASE_USER", os.environ.get("ANALYST_USERNAME", "")))
    parser.add_argument("--password", default=os.environ.get("SHOWCASE_PASSWORD", os.environ.get("ANALYST_PASSWORD", "")))
    args = parser.parse_args()

    if not args.password:
        print(
            "Set ANALYST_PASSWORD (or SHOWCASE_USER / SHOWCASE_PASSWORD) for analyst pages.\n"
            "Only /demo (client reports) works without login."
        )
    elif not args.user.strip():
        print(
            "[error] ANALYST_PASSWORD is set but username is empty.\n"
            "        Set SHOWCASE_USER or ANALYST_USERNAME to the same user you use at /login.\n"
            "        Example: $env:SHOWCASE_USER = 'analyst'"
        )
        sys.exit(1)

    ensure_playwright()
    capture(args.base, args.user.strip(), args.password, args.only)


if __name__ == "__main__":
    main()