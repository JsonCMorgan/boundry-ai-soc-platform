"""Regression tests for bugs caught by the CI lint gate (ruff F821 undefined names)."""


def test_add_task_to_soc_ticket_returns_task_list(analyst_client):
    """POST a task to an owned ticket returns the updated list (was a NameError 500)."""
    import app as app_module

    analyst_id = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("admin",)
    )["id"]
    app_module.db_run(
        f"INSERT INTO soc_cases (source, source_id, title, analyst_id, created_at) "
        f"VALUES ({app_module.PH}, {app_module.PH}, {app_module.PH}, {app_module.PH}, datetime('now'))",
        ("practice", "reg-1", "Regression ticket", analyst_id),
    )
    case_id = app_module.db_fetchone(
        f"SELECT id FROM soc_cases WHERE source_id = {app_module.PH}", ("reg-1",)
    )["id"]

    resp = analyst_client.post(
        f"/api/soc/cases/{case_id}/tasks", json={"title": "Pull 4625s for src IP"}
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"]
    assert any(t["title"] == "Pull 4625s for src IP" for t in body["tasks"])


def test_login_throttle_is_logged_to_siem(client):
    """Tripping the login rate limit writes a login_rate_limited SIEM event (was swallowed NameError)."""
    import app as app_module

    status = None
    for _ in range(40):
        status = client.post(
            "/login", data={"username": "admin", "password": "wrong"}
        ).status_code
        if status == 429:
            break
    assert status == 429

    row = app_module.db_fetchone(
        f"SELECT COUNT(*) AS n FROM siem_events WHERE event_type = {app_module.PH}",
        ("login_rate_limited",),
    )
    assert row["n"] >= 1


def test_api_ingest_mirrors_siem_with_tenant(analyst_client):
    """POST /api/ingest attaches client_id on siem_events via tenant slug."""
    import secrets

    import bcrypt

    import app as app_module

    api_key = secrets.token_urlsafe(32)
    app_module.db_run(
        f"INSERT INTO users (username, password, role, api_key, email) "
        f"VALUES ({app_module.PH}, {app_module.PH}, 'client', {app_module.PH}, {app_module.PH})",
        (
            "ingesttest",
            bcrypt.hashpw(b"x", bcrypt.gensalt()).decode(),
            api_key,
            "t@example.com",
        ),
    )
    uid = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("ingesttest",)
    )["id"]
    app_module.tenant_ops.ensure_tenant(
        app_module.db_run,
        app_module.db_fetchone,
        app_module.PH,
        uid,
        "ingesttest",
        display_name="Ingest Test",
    )

    resp = analyst_client.post(
        "/api/ingest",
        json={"event_type": "LOGIN_FAILED", "username": "bob", "ip": "10.0.0.5"},
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 201

    row = app_module.db_fetchone(
        f"SELECT client_id, event_type FROM siem_events WHERE src_ip = {app_module.PH} "
        f"ORDER BY id DESC LIMIT 1",
        ("10.0.0.5",),
    )
    assert row
    assert row["client_id"] == "ingesttest"
    assert row["event_type"] == "logon_failed"


def test_client_cannot_read_other_client_report(client):
    """Clients are blocked from viewing another tenant's report (403)."""
    import bcrypt

    import app as app_module

    pw = bcrypt.hashpw(b"Password1!", bcrypt.gensalt()).decode()
    app_module.db_run(
        f"INSERT INTO users (username, password, role) VALUES ({app_module.PH}, {app_module.PH}, 'client')",
        ("clienta", pw),
    )
    app_module.db_run(
        f"INSERT INTO users (username, password, role) VALUES ({app_module.PH}, {app_module.PH}, 'client')",
        ("clientb", pw),
    )
    id_a = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("clienta",)
    )["id"]
    id_b = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("clientb",)
    )["id"]
    app_module.db_run(
        f"INSERT INTO reports (content, threat_count, event_count, owner_id, simulated, report_type) "
        f"VALUES ({app_module.PH}, 0, 0, {app_module.PH}, 0, 'incident')",
        ("# Secret", id_b),
    )
    rid = app_module.db_fetchone("SELECT MAX(id) AS id FROM reports")["id"]

    client.post("/login", data={"username": "clienta", "password": "Password1!"})
    resp = client.get(f"/reports/{rid}")
    assert resp.status_code == 403


def test_client_cannot_open_soc_or_siem(client):
    """GAP-002: client role cannot reach analyst ops routes."""
    import bcrypt

    import app as app_module

    pw = bcrypt.hashpw(b"Password1!", bcrypt.gensalt()).decode()
    app_module.db_run(
        f"INSERT INTO users (username, password, role) VALUES ({app_module.PH}, {app_module.PH}, 'client')",
        ("portalonly", pw),
    )
    client.post("/login", data={"username": "portalonly", "password": "Password1!"})
    assert client.get("/soc").status_code == 404
    assert client.get("/siem").status_code == 404
    assert client.get("/career/shift").status_code == 404


def test_siem_api_tenant_filter(analyst_client):
    """GAP-003: ?tenant= limits SIEM API rows."""
    import app as app_module

    app_module.db_run(
        f"INSERT INTO siem_events (source, event_type, severity, client_id, description) "
        f"VALUES ({app_module.PH}, {app_module.PH}, {app_module.PH}, {app_module.PH}, {app_module.PH})",
        ("flask_app", "logon_failed", "HIGH", "tenant-a", "A"),
    )
    app_module.db_run(
        f"INSERT INTO siem_events (source, event_type, severity, client_id, description) "
        f"VALUES ({app_module.PH}, {app_module.PH}, {app_module.PH}, {app_module.PH}, {app_module.PH})",
        ("flask_app", "logon_failed", "HIGH", "tenant-b", "B"),
    )
    resp = analyst_client.get("/api/siem/events?tenant=tenant-a&limit=50")
    assert resp.status_code == 200
    events = resp.get_json().get("events") or []
    assert all(e.get("client_id") == "tenant-a" for e in events)


def test_alert_log_on_send_skip(client, monkeypatch):
    """GAP-006: failed send still writes alert_log row when Resend unset."""
    import app as app_module

    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    ok = app_module.send_email(
        "test@example.com",
        "Test",
        "<p>x</p>",
        severity="HIGH",
        ref_type="test",
        ref_id="1",
    )
    assert ok is False
    row = app_module.db_fetchone(
        f"SELECT ok, ref_type FROM alert_log WHERE recipient = {app_module.PH} ORDER BY id DESC LIMIT 1",
        ("test@example.com",),
    )
    assert row
    assert int(row["ok"]) == 0
    assert row["ref_type"] == "test"


def test_api_key_rotation_grace(analyst_client):
    """GAP-024: old key works during grace window after rotation."""
    import secrets

    import bcrypt

    import app as app_module
    import boundry_audit

    old_key = secrets.token_urlsafe(32)
    pw = bcrypt.hashpw(b"x", bcrypt.gensalt()).decode()
    app_module.db_run(
        f"INSERT INTO users (username, password, role, api_key) "
        f"VALUES ({app_module.PH}, {app_module.PH}, 'client', {app_module.PH})",
        ("rotateme", pw, old_key),
    )
    uid = app_module.db_fetchone(
        f"SELECT id FROM users WHERE username = {app_module.PH}", ("rotateme",)
    )["id"]
    rot = boundry_audit.rotate_client_api_key(
        app_module.db_run, app_module.db_fetchone, app_module.PH, uid
    )
    assert rot["ok"]
    assert app_module.boundry_audit.resolve_ingest_api_key(
        app_module.db_fetchone, app_module.PH, old_key
    )
    assert app_module.boundry_audit.resolve_ingest_api_key(
        app_module.db_fetchone, app_module.PH, rot["api_key"]
    )


def test_live_mode_blocks_training(analyst_client, monkeypatch):
    """GAP-008: BOUNDRY_MODE=live returns 404 on /training."""
    import app as app_module

    monkeypatch.setattr(app_module, "boundry_live_mode", lambda: True)
    assert analyst_client.get("/training").status_code == 404
