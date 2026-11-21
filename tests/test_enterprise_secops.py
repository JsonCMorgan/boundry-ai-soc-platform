"""Enterprise SecOps upgrade: IOC stub, mission queue, SIEM views."""
from __future__ import annotations

import json

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


def test_soc_ioc_stub_sql_injection_ip():
    import soc_ioc_stub

    r = soc_ioc_stub.lookup_ioc("192.0.2.55")
    assert r["ok"] is True
    assert r["verdict"] == "suspicious"


def test_siem_detections_api(analyst_client):
    r = analyst_client.get("/api/siem/detections")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    assert "detections" in r.get_json()


def test_saved_search_crud(analyst_client):
    r = analyst_client.post(
        "/api/siem/saved-searches",
        json={"name": "Test filter", "query": {"severity": "HIGH"}},
        content_type="application/json",
    )
    assert r.status_code == 200
    assert r.get_json()["ok"] is True
    listed = analyst_client.get("/api/siem/saved-searches").get_json()
    assert any(s["name"] == "Test filter" for s in listed["searches"])


def test_mission_control_queue(analyst_client):
    r = analyst_client.get("/api/soc/mission/queue")
    assert r.status_code == 200
    data = r.get_json()
    assert data["ok"] is True
    assert isinstance(data["items"], list)


def test_secops_summary(analyst_client):
    r = analyst_client.get("/api/control-room/secops-summary")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ok"] is True
    assert "open_findings" in d
    assert "attention" in d


def test_soc_enrich_uses_stub(analyst_client):
    r = analyst_client.post(
        "/api/soc/enrich",
        json={"ioc": "192.0.2.55"},
        content_type="application/json",
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("ok") is True or body.get("verdict") == "suspicious"
