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
