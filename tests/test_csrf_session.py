"""CSRF + session-persistence regression suite.

Pins the root cause found on 2026-10-01: the development server was started
with ``SESSION_COOKIE_SECURE=1`` while serving plain HTTP. The browser stored
the ``Secure`` cookie and then never sent it back, so Flask-WTF had no session
token to compare against and every POST failed with "CSRF validation failed".
The CSRF token itself was always rendered and always submitted.

These tests pin the *cause*, not the symptom:

* the session must survive across requests;
* the dev entry point must refuse a cookie policy that cannot work over HTTP;
* missing / invalid / foreign / expired tokens must still be rejected.

Nothing here relaxes CSRF.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from app import create_app
from tests.conftest import ADMIN_PASSWORD, make_app

ROOT = Path(__file__).resolve().parents[1]


def _token(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    assert match, f"no csrf_token rendered on {path}"
    return match.group(1)


@pytest.fixture()
def live_app(tmp_path):
    """App with CSRF genuinely enabled, plus one admin account."""
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


# 1 --------------------------------------------------------------------------
def test_get_root_does_not_trigger_csrf(live_app):
    response = live_app.test_client().get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert b"CSRF" not in response.data


# 2 --------------------------------------------------------------------------
def test_get_login_works(live_app):
    assert live_app.test_client().get("/login").status_code == 200


# 3 --------------------------------------------------------------------------
def test_login_page_contains_csrf_token(live_app):
    assert len(_token(live_app.test_client())) > 20


# 4 --------------------------------------------------------------------------
def test_valid_login_token_succeeds(live_app):
    client = live_app.test_client()
    response = client.post("/login", data={
        "csrf_token": _token(client), "username": "admin",
        "password": ADMIN_PASSWORD}, follow_redirects=True)
    assert response.status_code == 200
    assert b"CSRF validation failed" not in response.data
    assert client.get("/dashboard").status_code == 200


# 5 --------------------------------------------------------------------------
def test_missing_token_fails(live_app):
    client = live_app.test_client()
    client.get("/login")
    response = client.post("/login", data={"username": "admin",
                                           "password": ADMIN_PASSWORD})
    assert response.status_code == 400
    assert b"CSRF validation failed" in response.data


# 6 --------------------------------------------------------------------------
def test_invalid_token_fails(live_app):
    client = live_app.test_client()
    client.get("/login")
    response = client.post("/login", data={
        "csrf_token": "clearly-not-valid", "username": "admin",
        "password": ADMIN_PASSWORD})
    assert response.status_code == 400


# 7 --------------------------------------------------------------------------
def test_session_persists_between_get_requests(live_app):
    """The exact property whose absence caused the bug."""
    client = live_app.test_client()
    client.get("/login")                      # issues the session
    first = client.get("/__debug__/session").get_json()
    second = client.get("/__debug__/session").get_json()
    assert first["session_cookie_present"] is True
    assert second["session_cookie_present"] is True
    assert second["csrf_session_present"] is True


# 8 --------------------------------------------------------------------------
def test_csrf_token_stays_valid_within_the_same_session(live_app):
    """A token minted on one page must work on a later request."""
    client = live_app.test_client()
    token = _token(client)
    client.get("/")                            # unrelated navigation
    client.get("/login")
    response = client.post("/login", data={
        "csrf_token": token, "username": "admin",
        "password": ADMIN_PASSWORD}, follow_redirects=True)
    assert response.status_code == 200
    assert b"CSRF validation failed" not in response.data


# 9 --------------------------------------------------------------------------
def test_secret_key_is_stable_across_application_restarts():
    """A changing dev secret would invalidate every live session."""
    keys = {create_app("development").config["SECRET_KEY"] for _ in range(3)}
    assert len(keys) == 1, "development SECRET_KEY must not change per app build"


def test_exactly_one_csrfprotect_instance_is_bound_to_the_app():
    from app.extensions import csrf as shared

    app = create_app("development")
    assert app.extensions.get("csrf") is shared


def test_csrf_secret_is_not_regenerated_per_request(live_app):
    """Two requests must validate against the same signing secret."""
    client = live_app.test_client()
    token = _token(client)
    assert client.post("/login", data={
        "csrf_token": token, "username": "admin",
        "password": ADMIN_PASSWORD}).status_code in (302, 200)


# 10 -------------------------------------------------------------------------
def test_development_http_cookie_configuration():
    app = create_app("development")
    assert app.config["SESSION_COOKIE_SECURE"] is False, (
        "Secure cookies are never returned over http:// - this is the bug")
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


# 11 -------------------------------------------------------------------------
def test_production_https_cookie_configuration(monkeypatch):
    import secrets as _secrets

    monkeypatch.setenv("SECRET_KEY", _secrets.token_urlsafe(48))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    app = create_app("production")
    assert app.config["SESSION_COOKIE_SECURE"] is True
    assert app.config["WTF_CSRF_ENABLED"] is True


def test_dev_entrypoint_refuses_secure_cookies_over_http(monkeypatch):
    """run.py must fail loudly rather than serve an unusable session.

    This is the structural guard: the misconfiguration is invisible from the
    server side and nearly undiagnosable from the browser, so it is rejected
    at startup instead of surfacing later as a CSRF error.
    """
    env = {**dict(__import__("os").environ), "SESSION_COOKIE_SECURE": "1",
           "FLASK_CONFIG": "development"}
    env.pop("ALLOW_SECURE_COOKIE_OVER_HTTP", None)
    proc = subprocess.run([sys.executable, "run.py"], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 1, "run.py should refuse to start"
    assert "SESSION_COOKIE_SECURE=1" in proc.stderr
    assert "SESSION_COOKIE_SECURE=0" in proc.stderr      # states the remedy
    assert "Traceback" not in proc.stderr


def test_dev_entrypoint_allows_an_explicit_tls_proxy_override():
    """Behind a TLS-terminating proxy the combination is legitimate."""
    source = (ROOT / "run.py").read_text(encoding="utf-8")
    assert "ALLOW_SECURE_COOKIE_OVER_HTTP" in source


# 12 -------------------------------------------------------------------------
def test_every_state_changing_form_contains_a_csrf_token():
    offenders = []
    for path in (ROOT / "app" / "templates").rglob("*.html"):
        for match in re.finditer(
                r'<form\b[^>]*method\s*=\s*["\']?post["\']?[^>]*>(.*?)</form>',
                path.read_text(encoding="utf-8"), re.I | re.S):
            body = match.group(1)
            if "hidden_tag()" not in body and "csrf_token" not in body:
                offenders.append(path.name)
    assert not offenders, f"POST forms missing a CSRF token: {offenders}"


def test_no_state_changing_form_posts_to_an_implicit_url():
    offenders = []
    for path in (ROOT / "app" / "templates").rglob("*.html"):
        for match in re.finditer(r'<form\b([^>]*)>', path.read_text(encoding="utf-8"), re.I):
            attrs = match.group(1)
            method = (re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.I) or [None, "get"])[1]
            action = re.search(r'action\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
            if method.lower() == "post" and (action is None or action.group(1).strip() in ("", "/")):
                offenders.append(f"{path.name}: {attrs.strip()[:50]}")
    assert not offenders, f"POST forms with no explicit action: {offenders}"


# 13 -------------------------------------------------------------------------
def test_javascript_unsafe_request_mechanism_is_available(live_app):
    """JS must be able to obtain the token the supported way."""
    html = live_app.test_client().get("/login").get_data(as_text=True)
    assert re.search(r'<meta name="csrf-token" content="[^"]+"', html)
    app_js = (ROOT / "app" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "X-CSRFToken" in app_js
    assert 'meta[name="csrf-token"]' in app_js


def test_no_javascript_makes_an_unsafe_request_without_the_helper():
    """Any fetch/XHR that mutates state must route through pgFetch."""
    offenders = []
    for js in (ROOT / "app" / "static" / "js").rglob("*.js"):
        text = js.read_text(encoding="utf-8")
        for match in re.finditer(r'\bfetch\s*\(', text):
            window = text[match.start():match.start() + 400]
            if re.search(r'method\s*:\s*["\'](POST|PUT|PATCH|DELETE)', window, re.I):
                if "X-CSRFToken" not in window and "pgFetch" not in window:
                    offenders.append(js.name)
    assert not offenders, f"unsafe fetch without a CSRF header: {offenders}"


# 14 + 15 --------------------------------------------------------------------
def test_session_authenticated_api_write_requires_csrf(live_app):
    client = live_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    response = client.post("/api/analyze/url", json={"url": "https://example.com/"})
    assert response.status_code == 403
    assert response.get_json()["error"]["code"] == "csrf_required"


def test_api_key_authentication_does_not_require_csrf(live_app):
    from app.extensions import db as _db
    from app.models.user import User

    with live_app.app_context():
        raw = User.query.filter_by(username="admin").one().rotate_api_key()
        _db.session.commit()
    response = live_app.test_client().post(
        "/api/analyze/url", json={"url": "https://example.com/"},
        headers={"X-API-Key": raw})
    assert response.status_code == 200
    assert response.get_json()["success"] is True


# 16 -------------------------------------------------------------------------
def test_logout_invalidates_the_session(live_app):
    client = live_app.test_client()
    client.post("/login", data={"csrf_token": _token(client), "username": "admin",
                                "password": ADMIN_PASSWORD}, follow_redirects=True)
    assert client.get("/dashboard").status_code == 200
    client.get("/logout")
    assert client.get("/dashboard").status_code in (302, 401)
    assert client.get("/__debug__/session").get_json()["authenticated"] is False


# 17 -------------------------------------------------------------------------
def test_expired_token_fails_safely(tmp_path):
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

    import time as _time
    real = _time.time
    monkey = pytest.MonkeyPatch()
    monkey.setattr(_time, "time", lambda: real() + 3600)
    try:
        assert client.post("/login", data={
            "csrf_token": token, "username": "admin",
            "password": ADMIN_PASSWORD}).status_code == 400
    finally:
        monkey.undo()


# 18 -------------------------------------------------------------------------
def test_fresh_token_works_after_a_failure(live_app):
    client = live_app.test_client()
    client.get("/login")
    assert client.post("/login", data={"username": "admin"}).status_code == 400
    response = client.post("/login", data={
        "csrf_token": _token(client), "username": "admin",
        "password": ADMIN_PASSWORD}, follow_redirects=True)
    assert response.status_code == 200
    assert b"CSRF validation failed" not in response.data


# Diagnostics ----------------------------------------------------------------
def test_debug_session_endpoint_is_development_only(live_app, monkeypatch):
    import secrets as _secrets

    body = live_app.test_client().get("/__debug__/session").get_json()
    for key in ("session_cookie_present", "csrf_session_present", "authenticated",
                "scheme", "host", "secure_cookie", "samesite"):
        assert key in body

    monkeypatch.setenv("SECRET_KEY", _secrets.token_urlsafe(48))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    prod = create_app("production")
    assert prod.test_client().get("/__debug__/session").status_code == 404


def test_debug_session_endpoint_leaks_no_secrets(live_app):
    client = live_app.test_client()
    client.get("/login")
    raw = client.get("/__debug__/session").get_data(as_text=True)
    assert live_app.config["SECRET_KEY"] not in raw
    assert "csrf_token" not in raw.replace("csrf_session_present", "")


def test_csrf_failure_is_logged_with_presence_only_diagnostics(live_app, caplog):
    """The log must say WHY, without ever recording the token."""
    import logging

    # The security logger deliberately does not propagate (it has its own JSON
    # handler), so caplog cannot see it by default - capture it directly.
    records = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    logger = logging.getLogger("phishguard.security")
    handler = _Capture()
    logger.addHandler(handler)
    try:
        client = live_app.test_client()
        client.get("/login")
        client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD})
    finally:
        logger.removeHandler(handler)
    rejected = [r for r in records if getattr(r, "action", "") == "csrf_rejected"]
    assert rejected, "a CSRF rejection must be logged"
    fields = rejected[0].extra_fields
    assert fields["csrf_form"] == "MISSING"
    assert fields["session_cookie"] in ("PRESENT", "MISSING")

    # The real property: no token VALUE is recorded. Flask-WTF's reason text
    # legitimately contains the word "token" ("The CSRF token is missing."),
    # so assert on shape - a CSRF token is a long opaque string - rather than
    # on the word.
    import re as _re

    blob = str(fields)
    assert not _re.search(r"[A-Za-z0-9_\-]{32,}\.[A-Za-z0-9_\-]{16,}", blob), (
        f"a token-shaped value was logged: {blob[:120]}")
    for value in fields.values():
        if isinstance(value, str) and len(value) > 40:
            assert " " in value, f"long opaque value logged: {value[:60]}"
    assert live_app.config["SECRET_KEY"] not in blob
