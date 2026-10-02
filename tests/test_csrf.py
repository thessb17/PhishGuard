"""Regression tests for the CSRF / session-cookie failure.

Reported symptom: HTTP 400 "CSRF validation failed - Your session token
expired or was missing" while browsing the application.

Root cause: the session cookie was not reaching the server, so the session
(and the CSRF token stored in it) was absent when the form token arrived.
Two ways that happens are covered here:

* the cookie is withheld by the browser (cross-origin iframe + SameSite=Lax);
* the cookie is present but unverifiable (stale, signed with another key).

These tests pin BOTH the positive path (valid token works) and the negative
path (missing/invalid/foreign token is still rejected). Nothing here relaxes
CSRF - the point is that it must keep failing closed while legitimate use
keeps working.
"""

from __future__ import annotations

import re

import pytest

from app import create_app
from app.utils.session_policy import evaluate_session_policy
from tests.conftest import ADMIN_PASSWORD, make_app


def _token(client, path="/login"):
    """Fetch a page and extract its CSRF token."""
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, f"no csrf_token rendered on {path}"
    return match.group(1)


@pytest.fixture()
def csrf_app(tmp_path):
    """A real app with CSRF switched ON (the default test app disables it)."""
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True)
    from app.extensions import db as _db
    from app.models.user import Role, User

    with app.app_context():
        _db.create_all()
        user = User(username="admin", email="a@cybersafe.edu",
                    full_name="Avery Sinclair", role=Role.ADMIN)
        user.set_password(ADMIN_PASSWORD)
        user.ensure_api_key()
        _db.session.add(user)
        _db.session.commit()
    return app


# ---------------------------------------------------------------------------
# The reported symptom
# ---------------------------------------------------------------------------


def test_root_get_never_requires_csrf(csrf_app):
    """GET / is a redirect; it must never reach the CSRF handler."""
    client = csrf_app.test_client()
    response = client.get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert b"CSRF" not in response.data


def test_root_post_is_method_not_allowed_not_a_csrf_error(csrf_app):
    """POST / has no route, so it must be 405 - not a confusing CSRF 400."""
    response = csrf_app.test_client().post("/", data={"x": "1"})
    assert response.status_code == 405


def test_login_with_valid_csrf_succeeds(csrf_app):
    client = csrf_app.test_client()
    token = _token(client)
    response = client.post("/login", data={
        "csrf_token": token, "username": "admin", "password": ADMIN_PASSWORD,
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"CSRF validation failed" not in response.data


def test_login_without_csrf_fails(csrf_app):
    client = csrf_app.test_client()
    client.get("/login")
    response = client.post("/login",
                           data={"username": "admin", "password": ADMIN_PASSWORD})
    assert response.status_code == 400
    assert b"CSRF validation failed" in response.data


def test_login_with_invalid_csrf_fails(csrf_app):
    client = csrf_app.test_client()
    client.get("/login")
    response = client.post("/login", data={
        "csrf_token": "not-a-real-token", "username": "admin",
        "password": ADMIN_PASSWORD,
    })
    assert response.status_code == 400
    assert b"CSRF validation failed" in response.data


def test_valid_token_without_the_session_cookie_is_rejected(csrf_app):
    """The exact reported failure, reproduced.

    A browser that withholds the session cookie (cross-origin iframe with a
    Lax cookie, or blocked cookies) sends a well-formed token with no session
    to validate it against. That must still be rejected - and it must produce
    the explanatory page, not a bare error.
    """
    issuing = csrf_app.test_client()
    token = _token(issuing)

    cookieless = csrf_app.test_client()   # separate client => no session cookie
    response = cookieless.post("/login", data={
        "csrf_token": token, "username": "admin", "password": ADMIN_PASSWORD,
    })
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert "CSRF validation failed" in body
    assert "Why this usually happens" in body


def test_token_from_another_session_is_rejected(csrf_app):
    """Token fixation across sessions must not work."""
    victim = csrf_app.test_client()
    attacker = csrf_app.test_client()
    stolen = _token(attacker)
    victim.get("/login")
    response = victim.post("/login", data={
        "csrf_token": stolen, "username": "admin", "password": ADMIN_PASSWORD,
    })
    assert response.status_code == 400


def test_csrf_error_has_safe_message(csrf_app):
    """The error page must explain, and must leak nothing."""
    client = csrf_app.test_client()
    client.get("/login")
    body = client.post("/login", data={"username": "admin"}).get_data(as_text=True)

    assert "CSRF validation failed" in body
    assert "Sign in again" in body and "Reload" in body
    for leak in ("Traceback", "SECRET_KEY", "werkzeug", "csrf_token\":",
                 csrf_app.config["SECRET_KEY"]):
        assert leak not in body, f"CSRF page leaked {leak!r}"


def test_csrf_token_present_on_login_page(csrf_app):
    assert _token(csrf_app.test_client())


def test_fresh_page_issues_a_usable_token_after_a_failure(csrf_app):
    """Recovery path: reloading must produce a token that works."""
    client = csrf_app.test_client()
    client.get("/login")
    assert client.post("/login", data={"username": "admin"}).status_code == 400
    token = _token(client)          # reload
    response = client.post("/login", data={
        "csrf_token": token, "username": "admin", "password": ADMIN_PASSWORD,
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"CSRF validation failed" not in response.data


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------


def test_every_post_form_template_carries_a_csrf_token():
    """Static guarantee across all templates, not just the ones we browse."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    offenders = []
    for path in root.rglob("*.html"):
        for match in re.finditer(
                r'<form\b[^>]*method\s*=\s*["\']?post["\']?[^>]*>(.*?)</form>',
                path.read_text(encoding="utf-8"), re.I | re.S):
            inner = match.group(1)
            if "hidden_tag()" not in inner and "csrf_token" not in inner:
                offenders.append(path.name)
    assert not offenders, f"POST forms without a CSRF token: {offenders}"


def test_no_post_form_relies_on_an_implicit_action():
    """A POST form with no action submits to the current URL, which changes
    with redirects and query strings. Every one must name its endpoint."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1] / "app" / "templates"
    offenders = []
    for path in root.rglob("*.html"):
        for match in re.finditer(r'<form\b([^>]*)>', path.read_text(encoding="utf-8"), re.I):
            attrs = match.group(1)
            method = (re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.I) or [None, "get"])[1]
            action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            if method.lower() == "post" and (action is None or action.group(1).strip() in ("", "/")):
                offenders.append(f"{path.name}: {attrs.strip()[:60]}")
    assert not offenders, f"POST forms with no explicit action: {offenders}"


def test_csrf_meta_tag_is_published_for_javascript(csrf_app):
    html = csrf_app.test_client().get("/login").get_data(as_text=True)
    assert re.search(r'<meta name="csrf-token" content="[^"]+"', html)


# ---------------------------------------------------------------------------
# Session-cookie policy validation
# ---------------------------------------------------------------------------


def test_development_http_cookie_configuration():
    """Local HTTP development must not use Secure cookies."""
    app = create_app("development")
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


def test_production_keeps_secure_cookies(monkeypatch):
    import secrets as _secrets

    monkeypatch.setenv("SECRET_KEY", _secrets.token_urlsafe(48))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    app = create_app("production")
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_session_cookie_flags_on_a_real_response(csrf_app):
    cookie = csrf_app.test_client().get("/login").headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie
    assert "SameSite" in cookie


@pytest.mark.parametrize("config,expected_code", [
    ({"SESSION_COOKIE_SAMESITE": "None", "SESSION_COOKIE_SECURE": False,
      "ENV_NAME": "development", "FRAME_ANCESTORS": "'self'"},
     "samesite_none_without_secure"),
    ({"SESSION_COOKIE_SAMESITE": "Lax", "SESSION_COOKIE_SECURE": True,
      "ENV_NAME": "development", "FRAME_ANCESTORS": "'self'"},
     "secure_cookie_on_http_dev"),
    ({"SESSION_COOKIE_SAMESITE": "Lax", "SESSION_COOKIE_SECURE": False,
      "ENV_NAME": "development", "FRAME_ANCESTORS": "'self' https://*.example.com"},
     "embedded_with_lax_cookie"),
    ({"SESSION_COOKIE_SAMESITE": "Lax", "SESSION_COOKIE_SECURE": False,
      "ENV_NAME": "development", "FRAME_ANCESTORS": "'self'",
      "WTF_CSRF_ENABLED": False},
     "csrf_disabled"),
])
def test_policy_validator_detects_broken_cookie_configurations(config, expected_code):
    """Each combination silently breaks sessions; each must be reported."""
    config.setdefault("WTF_CSRF_ENABLED", True)
    codes = [p["code"] for p in evaluate_session_policy(config)]
    assert expected_code in codes


def test_policy_validator_is_quiet_on_a_correct_local_configuration():
    assert evaluate_session_policy({
        "SESSION_COOKIE_SAMESITE": "Lax", "SESSION_COOKIE_SECURE": False,
        "ENV_NAME": "development", "FRAME_ANCESTORS": "'self'",
        "WTF_CSRF_ENABLED": True,
    }) == []


def test_policy_validator_accepts_a_correct_embedded_configuration():
    """SameSite=None + Secure is the supported way to be framed cross-origin."""
    assert evaluate_session_policy({
        "SESSION_COOKIE_SAMESITE": "None", "SESSION_COOKIE_SECURE": True,
        "ENV_NAME": "production", "FRAME_ANCESTORS": "'self' https://*.example.com",
        "WTF_CSRF_ENABLED": True,
    }) == []


# ---------------------------------------------------------------------------
# Development session reset
# ---------------------------------------------------------------------------


def test_session_reset_is_development_only(csrf_app, monkeypatch):
    import secrets as _secrets

    response = csrf_app.test_client().get("/auth/session-reset")
    assert response.status_code in (302, 303)
    assert "/login" in response.headers["Location"]

    monkeypatch.setenv("SECRET_KEY", _secrets.token_urlsafe(48))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    prod = create_app("production")
    assert prod.test_client().get("/auth/session-reset").status_code == 404


def test_session_reset_clears_the_login_session(csrf_app):
    client = csrf_app.test_client()
    token = _token(client)
    client.post("/login", data={"csrf_token": token, "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    assert client.get("/dashboard").status_code == 200

    client.get("/auth/session-reset")
    assert client.get("/dashboard").status_code in (302, 401)


# ---------------------------------------------------------------------------
# API CSRF architecture (item 16)
# ---------------------------------------------------------------------------


def test_session_authenticated_api_write_requires_csrf(csrf_app):
    """Cookie-authenticated writes are forgeable without a token."""
    client = csrf_app.test_client()
    token = _token(client)
    client.post("/login", data={"csrf_token": token, "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    response = client.post("/api/analyze/url", json={"url": "https://example.com/"})
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "csrf_required"


def test_api_key_authenticated_write_does_not_require_csrf(csrf_app):
    """API keys are not ambient browser credentials, so CSRF does not apply."""
    from app.extensions import db as _db
    from app.models.user import User

    with csrf_app.app_context():
        user = User.query.filter_by(username="admin").one()
        raw = user.rotate_api_key()
        _db.session.commit()

    response = csrf_app.test_client().post(
        "/api/analyze/url", json={"url": "https://example.com/"},
        headers={"X-API-Key": raw})
    assert response.status_code == 200
    assert response.get_json()["success"] is True


def test_api_csrf_failure_returns_json_not_html(csrf_app):
    client = csrf_app.test_client()
    token = _token(client)
    client.post("/login", data={"csrf_token": token, "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    response = client.post("/api/analyze/url", json={"url": "https://example.com/"})
    assert response.headers["Content-Type"].startswith("application/json")
    body = response.get_json()
    assert body["success"] is False
    assert body["data"] is None
    assert body["error"]["code"] == "csrf_required"
    assert "request_id" in body


# ---------------------------------------------------------------------------
# Token lifetime
# ---------------------------------------------------------------------------


def test_csrf_time_limit_is_finite_and_configurable(csrf_app):
    """Expiry must not be disabled to make the problem disappear."""
    limit = csrf_app.config["WTF_CSRF_TIME_LIMIT"]
    assert limit is not None, "CSRF expiry must not be disabled"
    assert 0 < int(limit) <= 86400


def test_expired_token_is_rejected_and_reload_recovers(tmp_path):
    """An expired token must fail closed, and a reload must then work.

    The expiry is forced by rewinding the signer's clock rather than by
    sleeping: itsdangerous timestamps have one-second granularity, so a
    sleep-based test sits right on the boundary and is flaky (observed
    failing 2 runs in 3). Freezing time makes the assertion deterministic.
    """
    workdir = tmp_path / "expiry"
    workdir.mkdir()
    app = make_app(workdir, WTF_CSRF_ENABLED=True, WTF_CSRF_TIME_LIMIT=1)
    from app.extensions import db as _db
    from app.models.user import Role, User

    with app.app_context():
        _db.create_all()
        u = User(username="admin", email="a@cybersafe.edu", full_name="A", role=Role.ADMIN)
        u.set_password(ADMIN_PASSWORD)
        _db.session.add(u)
        _db.session.commit()

    client = app.test_client()
    token = _token(client)

    # Advance the clock well past the 1-second limit.
    import time as _time

    real_time = _time.time
    monkey = pytest.MonkeyPatch()
    monkey.setattr(_time, "time", lambda: real_time() + 3600)
    try:
        expired = client.post("/login", data={
            "csrf_token": token, "username": "admin", "password": ADMIN_PASSWORD})
        assert expired.status_code == 400, "an expired token must be rejected"
    finally:
        monkey.undo()

    fresh = _token(client)                # reload issues a new one
    ok = client.post("/login", data={
        "csrf_token": fresh, "username": "admin", "password": ADMIN_PASSWORD},
        follow_redirects=True)
    assert ok.status_code == 200
    assert b"CSRF validation failed" not in ok.data
