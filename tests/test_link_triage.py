"""Offline link check API (Option B phone + CLI companion)."""

from __future__ import annotations

import pytest


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
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["user_id"] = row["id"]
        sess["role"] = "analyst"
    return client


def test_api_link_check_paradox_intact(analyst_client):
    resp = analyst_client.post(
        "/api/ops/link-check",
        json={
            "url": "https://olivia.paradox.ai/candidates/apply/test",
            "claimed_brand": "Intact Financial",
        },
    )
    if resp.status_code == 503:
        pytest.skip("link-check package not installed (pip install -e ../link-check)")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["verdict"] == "do_not_click"
    assert "brand_mismatch" in data["signals"]


def test_api_link_check_requires_url(analyst_client):
    resp = analyst_client.post("/api/ops/link-check", json={})
    assert resp.status_code == 400