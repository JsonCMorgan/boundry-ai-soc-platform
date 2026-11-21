"""Spot-check stacked writing coach markup on key pages."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def analyst_client(client):
    import app as app_module

    app_module.db_run(
        f"UPDATE users SET role = {app_module.PH} WHERE username = {app_module.PH}",
        ("analyst", "admin"),
    )
    row = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("admin",)
    )
    assert row
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["user_id"] = row["id"]
        sess["role"] = "analyst"
    return client


def test_report_detail_has_writing_coach(analyst_client):
    """Incident report notes show persistent coach + aria link."""
    import app as app_module

    app_module.db_run(
        "INSERT INTO reports (content, created_at) VALUES (?, datetime('now'))",
        ("Writing coach test body",),
    )
    row = app_module.db_fetchone("SELECT id FROM reports ORDER BY id DESC LIMIT 1")
    assert row
    r = analyst_client.get(f"/reports/{row['id']}")
    if r.status_code == 404:
        pytest.skip("report route unavailable")
    html = r.get_data(as_text=True)
    assert "writing-coach" in html
    assert 'coach-report_investigation' in html
    assert 'aria-describedby="coach-report_investigation"' in html
    assert 'data-writing-coach="report_investigation"' in html


def test_career_intel_case_has_coach(analyst_client):
    import intel_lab

    case_id = intel_lab.list_cases()[0]["id"] if intel_lab.list_cases() else ""
    if not case_id:
        pytest.skip("no intel cases")
    r = analyst_client.get(f"/career/intel/{case_id}?seed=testseed")
    if r.status_code == 404:
        pytest.skip("intel case route unavailable")
    html = r.get_data(as_text=True)
    assert "coach-career_intel_note" in html
    assert 'data-writing-coach="career_intel_note"' in html


def test_note_coach_audit_strict():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "note_coach_audit.py"), "--strict"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
