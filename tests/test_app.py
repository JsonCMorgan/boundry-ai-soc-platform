"""
Smoke + regression tests for the patched `main` branch behavior.
"""
from urllib.parse import quote

# A password that satisfies the policy: 12+ chars, uppercase, digit, special char.
VALID_PASSWORD = "TestPass123!"


def test_index_ok(client):
    """Home route should return 200 and mention the brand name."""
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Boundry.AI" in resp.data


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


def test_reports_redirects_unauthenticated(client):
    """
    Unauthenticated GET /reports must return 302 and redirect to /login.
    The reports dashboard is protected by @login_required (A01).
    """
    resp = client.get("/reports")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_reports_ok_when_logged_in(logged_in_client):
    """
    GET /reports for an authenticated user must return 200.
    An empty reports table shows the onboarding empty state — not an error.
    """
    resp = logged_in_client.get("/reports")
    assert resp.status_code == 200
    assert b"Boundry.AI" in resp.data


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
    POST /login with correct credentials must return 302 and redirect to the
    reports dashboard. Verifies session is created on successful authentication (A07).
    """
    resp = client.post("/login", data={"username": "admin", "password": "admin123"})
    assert resp.status_code == 302
    assert "/reports" in resp.headers["Location"]


# --- Registration tests (A03: Injection, A07: Auth Failures) ---

def test_register_valid_redirects_to_login(client):
    """
    Happy path: valid registration must return 302 and redirect to /login.
    Verifies new users are created and sent to authenticate — never auto-logged in.
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": VALID_PASSWORD,
        "confirm":  VALID_PASSWORD,
    })
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_register_duplicate_username_rejected(client):
    """
    Duplicate username must return 200 with an error — no two users share a username.
    """
    client.post("/register", data={
        "username": "newuser",
        "password": VALID_PASSWORD,
        "confirm":  VALID_PASSWORD,
    })
    resp = client.post("/register", data={
        "username": "newuser",
        "password": VALID_PASSWORD,
        "confirm":  VALID_PASSWORD,
    })
    assert resp.status_code == 200
    assert b"Registration failed" in resp.data


def test_register_short_password_rejected(client):
    """
    Password under 12 characters must be rejected — enforces minimum password policy (A07).
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "Short1!",
        "confirm":  "Short1!",
    })
    assert resp.status_code == 200
    assert b"at least 12 characters" in resp.data


def test_register_no_uppercase_rejected(client):
    """
    Password without an uppercase letter must be rejected (A07).
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "alllowercase123!",
        "confirm":  "alllowercase123!",
    })
    assert resp.status_code == 200
    assert b"uppercase" in resp.data


def test_register_no_special_char_rejected(client):
    """
    Password without a special character must be rejected (A07).
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": "NoSpecialChar123",
        "confirm":  "NoSpecialChar123",
    })
    assert resp.status_code == 200
    assert b"special character" in resp.data


def test_register_short_username_rejected(client):
    """
    Username under 3 characters must be rejected.
    """
    resp = client.post("/register", data={
        "username": "ab",
        "password": VALID_PASSWORD,
        "confirm":  VALID_PASSWORD,
    })
    assert resp.status_code == 200
    assert b"between 3 and 50 characters" in resp.data


def test_register_mismatched_passwords_rejected(client):
    """
    Mismatched password and confirm fields must be rejected — catches registration typos.
    Both passwords individually meet the policy; only the mismatch should trigger an error.
    """
    resp = client.post("/register", data={
        "username": "newuser",
        "password": VALID_PASSWORD,
        "confirm":  "DifferentP1!xyz",
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
