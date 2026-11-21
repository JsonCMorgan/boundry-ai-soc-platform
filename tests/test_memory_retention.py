"""Boundry Retention Layer — scheduling and review flow."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
    assert row
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["user_id"] = row["id"]
        sess["role"] = "analyst"
    return client


def test_enroll_and_due_scheduling(analyst_client):
    import app as app_module
    import memory_retention

    aid = 999991
    memory_retention.enroll_items(
        aid,
        [{
            "item_id": "secplus:q:test_q1",
            "track": "secplus",
            "item_type": "mcq",
            "payload": {
                "lesson_id": "sp_d1_01_control_functions",
                "question_id": "test_q1",
            },
            "first_due_hours": 0,
        }],
        source="pytest",
    )
    assert memory_retention.due_count(aid) >= 1
    due = memory_retention.due_items(aid, limit=5)
    assert any(d["item_id"] == "secplus:q:test_q1" for d in due)

    out = memory_retention.record_review(
        aid, "secplus:q:test_q1", rating="good", correct=True, ms=1200,
    )
    assert out.get("ok")
    assert out.get("next_due")

    app_module.db_run(
        f"DELETE FROM retention_reviews WHERE analyst_id = {app_module.PH}",
        (aid,),
    )
    app_module.db_run(
        f"DELETE FROM retention_cards WHERE analyst_id = {app_module.PH}",
        (aid,),
    )
    app_module.db_run(
        f"DELETE FROM retention_items WHERE item_id = {app_module.PH}",
        ("secplus:q:test_q1",),
    )


def test_secplus_prove_enroll_sets_future_due(analyst_client):
    import memory_retention

    aid = 999992
    memory_retention.enroll_secplus_quiz_result(
        aid,
        "sp_d1_01_control_functions",
        [{"id": "sp_d1_01_p1", "correct": True}],
        passed=True,
    )
    import app as app_module

    row = app_module.db_fetchone(
        f"SELECT due_at FROM retention_cards WHERE analyst_id = {app_module.PH} LIMIT 1",
        (aid,),
    )
    assert row and row.get("due_at")
    due_at = datetime.strptime(row["due_at"][:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert due_at > datetime.now(timezone.utc) - timedelta(hours=1)

    app_module.db_run(f"DELETE FROM retention_cards WHERE analyst_id = {app_module.PH}", (aid,))
    app_module.db_run(f"DELETE FROM retention_items WHERE track = {app_module.PH}", ("secplus",))


def test_career_review_page_loads(analyst_client):
    r = analyst_client.get("/career/review")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "Daily Review" in html or "Review queue" in html
    assert "/api/career/review/due" in html
