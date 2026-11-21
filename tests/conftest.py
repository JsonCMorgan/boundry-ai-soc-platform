"""
Pytest fixtures: isolate the SQLite file so tests never touch your real app.db.
"""
import importlib
import os

import pytest

# Env flags that change which Sec+ spine/quiz banks load at import time.
# Some Messer tests set these directly on os.environ, so restore them after every test.
_MESSER_ENV_KEYS = (
    "ENABLE_MESSER_LAYER",
    "MESSER_QUIZ_FROM_NOTES",
    "MESSER_CONTENT_ROOT",
    "USE_MESSER_MINI",
)


@pytest.fixture(autouse=True)
def _restore_messer_env():
    """Undo Messer env flags leaked by a test and reload the modules that read them."""
    before = {k: os.environ.get(k) for k in _MESSER_ENV_KEYS}
    yield
    after = {k: os.environ.get(k) for k in _MESSER_ENV_KEYS}
    if after == before:
        return
    for key, value in before.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    import messer_curriculum
    import secplus_learn

    importlib.reload(messer_curriculum)
    importlib.reload(secplus_learn)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Flask test client with DB_PATH pointing at a temp database.

    Block job: import `app` after patching DB_PATH, seed rows, then hand back
    a client — same routes as production, zero side effects on disk in the project root.

    SEED_DB=true is set so init_db() populates the test DB with the lab accounts
    (admin/admin123, alice/alice456, bob/bob789) used by auth tests.
    """
    import app as app_module

    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setenv("SEED_DB", "true")   # populate lab users in the test DB
    monkeypatch.setenv("MESSER_QUIZ_SKIP_VERIFY", "1")
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    app_module.app.config["WTF_CSRF_ENABLED"] = False
    # Rate-limit counters are in-memory and shared across tests; start each test clean.
    app_module.limiter.reset()
    return app_module.app.test_client()


@pytest.fixture
def analyst_client(client):
    """Logged-in analyst session (required for Messer layer routes)."""
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


@pytest.fixture
def logged_in_client(client):
    """
    Same test client but with an active session (logged in as admin).

    Block job: POST valid credentials to /login so the session cookie is set,
    then return the client — use this for any route protected by @login_required.
    """
    client.post("/login", data={"username": "admin", "password": "admin123"})
    return client
