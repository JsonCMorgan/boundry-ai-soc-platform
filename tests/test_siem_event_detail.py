"""SIEM triage UX: event detail API, today filter, ticket open idempotency."""
from __future__ import annotations

from datetime import datetime

import pytest


@pytest.fixture
def analyst_client(client):
    """Lab admin seeded as client; promote to analyst for SIEM/SOC routes."""
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


def _insert_event(app_module, description: str = "test event", severity: str = "MEDIUM") -> int:
    app_module.db_run(
        f"INSERT INTO siem_events (created_at, source, event_id, event_type, severity, "
        f"description, src_ip, dismissed) "
        f"VALUES (datetime('now'), 'flask_app', 't1', 'test_triage', {app_module.PH}, "
        f"{app_module.PH}, '203.0.113.10', 0)",
        (severity, description),
    )
    row = app_module.db_fetchone("SELECT id FROM siem_events ORDER BY id DESC LIMIT 1")
    assert row
    return int(row["id"])


def test_siem_event_detail_ok(analyst_client, client):
    import app as app_module

    eid = _insert_event(app_module)
    resp = analyst_client.get(f"/api/siem/events/{eid}")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["event"]["id"] == eid
    assert data["observables"]["primary_ioc"] == "203.0.113.10"
    assert data["event"]["spl_hint"]
    assert "203.0.113.10" in data["event"]["spl_hint"]


def test_siem_event_detail_not_found(analyst_client):
    resp = analyst_client.get("/api/siem/events/999999")
    assert resp.status_code == 404


def test_siem_search_today_filter(analyst_client, client):
    import app as app_module

    ymd = datetime.utcnow().strftime("%Y-%m-%d")
    _insert_event(app_module, description="today filter probe")
    resp = analyst_client.get(f"/api/siem/search?from={ymd}&to={ymd}&limit=50")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] >= 1
    assert any("today filter probe" in (e.get("description") or "") for e in data["events"])


def test_soc_open_case_idempotent_for_siem(analyst_client, client):
    import app as app_module

    eid = _insert_event(app_module, description="ticket idempotency", severity="HIGH")
    payload = {"source": "siem", "source_id": str(eid)}
    r1 = analyst_client.post("/api/soc/cases/open", json=payload)
    r2 = analyst_client.post("/api/soc/cases/open", json=payload)
    assert r1.status_code == 200
    assert r2.status_code == 200
    d1 = r1.get_json()
    d2 = r2.get_json()
    assert d1["ok"] and d2["ok"]
    assert d1["case"]["id"] == d2["case"]["id"]
    assert d1["created"] is True
    assert d2["created"] is False

    detail = analyst_client.get(f"/api/siem/events/{eid}").get_json()
    assert detail["event"]["existing_case"]["id"] == d1["case"]["id"]


def test_siem_enrich_event_stub(analyst_client, client):
    import app as app_module

    app_module.db_run(
        f"INSERT INTO siem_events (created_at, source, event_id, event_type, severity, "
        f"description, src_ip, dismissed) "
        f"VALUES (datetime('now'), 'flask_app', 'enr', 'c2_callback', 'HIGH', "
        f"{app_module.PH}, {app_module.PH}, 0)",
        ("Callback to documentation C2", "203.0.113.88"),
    )
    row = app_module.db_fetchone("SELECT id FROM siem_events ORDER BY id DESC LIMIT 1")
    eid = int(row["id"])
    resp = analyst_client.post("/api/siem/enrich", json={"event_id": eid})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["source"] == "local_stub"
    assert data["event_id"] == eid
    assert any(e["indicator"] == "203.0.113.88" for e in data["enrichment"])
    hit = next(e for e in data["enrichment"] if e["indicator"] == "203.0.113.88")
    assert hit["verdict"] == "malicious"
    assert "203[.]0[.]113[.]88" == hit["defanged"]
    assert data["plain_summary"]


def test_siem_enrich_single_ioc_benign(analyst_client):
    resp = analyst_client.post("/api/siem/enrich", json={"ioc": "8.8.8.8"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["enrichment"][0]["verdict"] == "benign"


def test_siem_enrich_requires_body(analyst_client):
    resp = analyst_client.post("/api/siem/enrich", json={})
    assert resp.status_code == 400


def test_observables_from_siem_description(client):
    """IPs embedded in description appear when src_ip column is empty."""
    import app as app_module
    import soc_lab

    app_module.db_run(
        f"INSERT INTO siem_events (created_at, source, event_id, event_type, severity, "
        f"description, dismissed) VALUES (datetime('now'), 'flask_app', 'sim', 'sql injection', "
        f"'HIGH', {app_module.PH}, 0)",
        ("Simulated search user=admin from 192.0.2.55 — payload",),
    )
    row = app_module.db_fetchone("SELECT id FROM siem_events ORDER BY id DESC LIMIT 1")
    obs = soc_lab.observables_for_ticket(
        app_module.db_fetchone, "siem", str(row["id"]), ph=app_module.PH
    )
    assert obs["primary_ioc"] == "192.0.2.55"
    assert any(e["value"] == "192.0.2.55" for e in obs["entities"])
