"""
Smoke + regression tests for the patched `main` branch behavior.
"""
from urllib.parse import quote


def test_index_ok(client):
    """Home route should return 200 and mention the lab."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Vulnerable App" in resp.data


def test_search_parameterized_no_error(logged_in_client):
    """Search with a normal substring should return 200 (parameterized query)."""
    resp = logged_in_client.get("/search?q=alice")
    assert resp.status_code == 200
    assert b"alice" in resp.data.lower()


def test_greeting_escapes_script_tag(logged_in_client):
    """
    Reflected name must not render raw HTML — script should be escaped in the body.

    If we removed default escaping or added |safe in the template, this test would fail.
    """
    payload = "<script>alert(1)</script>"
    resp = logged_in_client.get("/greeting?name=" + quote(payload))
    assert resp.status_code == 200
    assert b"<script>" not in resp.data
    assert b"&lt;script&gt;" in resp.data


# --- Auth tests (A01: Broken Access Control, A07: Auth Failures) ---

def test_search_redirects_unauthenticated(client):
    """
    Unauthenticated GET /search must return 302 and redirect to /login.
    Verifies the @login_required decorator is enforcing access control (A01).
    """
    resp = client.get("/search")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_login_wrong_credentials(client):
    """
    POST /login with bad credentials must return 200 (re-render form) with a
    generic error — never reveal which field was wrong (A07).
    """
    resp = client.post("/login", data={"username": "admin", "password": "wrongpassword"})
    assert resp.status_code == 200
    assert b"Invalid username or password" in resp.data


def test_login_valid_credentials_redirects(client):
    """
    POST /login with correct credentials must return 302 and redirect to home.
    Verifies session is created on successful authentication (A07).
    """
    resp = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 302
    assert "/" in resp.headers["Location"]


# --- Registration tests (A03: Injection, A07: Auth Failures) ---

def test_register_valid_redirects_to_login(client):
    """
    Happy path: valid registration must return 302 and redirect to /login.
    Verifies new users are created and sent to authenticate — never auto-logged in.
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "securepass123",
        "confirm":  "securepass123",
    })
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_register_duplicate_username_rejected(client):
    """
    Duplicate username must return 200 with an error — no two users share a username.
    """
    client.post("/register", data={
        "username": "newuser",
        "password": "securepass123",
        "confirm":  "securepass123",
    })
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "anotherpass456",
        "confirm":  "anotherpass456",
    })
    assert resp.status_code == 200
    assert b"Registration failed" in resp.data


def test_register_short_password_rejected(client):
    """
    Password under 8 characters must be rejected — enforces minimum password policy (A07).
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "short",
        "confirm":  "short",
    })
    assert resp.status_code == 200
    assert b"at least 8 characters" in resp.data


def test_register_short_username_rejected(client):
    """
    Username under 3 characters must be rejected.
    """
    resp = client.post("/register", data={
        "username": "ab",
        "password": "securepass123",
        "confirm":  "securepass123",
    })
    assert resp.status_code == 200
    assert b"between 3 and 50 characters" in resp.data


def test_register_mismatched_passwords_rejected(client):
    """
    Mismatched password and confirm fields must be rejected — catches registration typos.
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "securepass123",
        "confirm":  "differentpass456",
    })
    assert resp.status_code == 200
    assert b"do not match" in resp.data


def test_register_empty_fields_rejected(client):
    """
    Empty username or password must be rejected — basic input validation.
    """
    resp = client.post("/register", data={
        "username": "",
        "password": "",
        "confirm":  "",
    })
    assert resp.status_code == 200
    assert b"required" in resp.data
