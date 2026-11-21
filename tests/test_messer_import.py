"""Messer layer tests (synthetic fixtures only — no copyrighted content in git)."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_parse_practice_exam_text():
    from tools.messer_import_questions import parse_practice_exam_text

    text = (ROOT / "tests" / "fixtures" / "messer_sample_exam.txt").read_text(encoding="utf-8")
    items = parse_practice_exam_text(text, "fixture_exam", provenance={"test": True})
    assert len(items) >= 2
    assert items[0]["item_id"].startswith("messer:pe:fixture_exam:")
    assert len(items[0]["choices"]) >= 2


def test_messer_routes_hidden_without_flag(analyst_client):
    import messer_layer

    old = __import__("os").environ.get("ENABLE_MESSER_LAYER")
    try:
        __import__("os").environ.pop("ENABLE_MESSER_LAYER", None)
        r = analyst_client.get("/career/secplus/messer")
        assert r.status_code == 404
    finally:
        if old is not None:
            __import__("os").environ["ENABLE_MESSER_LAYER"] = old


def test_messer_routes_block_demo(client):
    import os

    os.environ["ENABLE_MESSER_LAYER"] = "1"
    with client.session_transaction() as sess:
        sess["username"] = "demo"
        sess["user_id"] = 999
        sess["role"] = "analyst"
    r = client.get("/career/secplus/messer")
    assert r.status_code == 403


def test_messer_routes_ok_with_flag(analyst_client):
    import os

    os.environ["ENABLE_MESSER_LAYER"] = "1"
    r = analyst_client.get("/career/secplus/messer")
    assert r.status_code == 200


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
