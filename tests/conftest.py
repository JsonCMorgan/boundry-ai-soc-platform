"""
Pytest fixtures: isolate the SQLite file so tests never touch your real app.db.
"""
import pytest


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
    app_module.init_db()
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture
def logged_in_client(client):
    """
    Same test client but with an active session (logged in as admin).

    Block job: POST valid credentials to /login so the session cookie is set,
    then return the client — use this for any route protected by @login_required.
    """
    client.post("/login", data={"username": "admin", "password": "admin123"})
    return client
