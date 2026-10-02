"""Transport-level and application-level security controls."""

from __future__ import annotations

import pytest

from app import create_app
from app.extensions import db as _db
from app.models.audit_log import AuditAction, AuditLog
from app.models.user import Role, User
from scripts.security_check import run_checks
from tests.conftest import ADMIN_PASSWORD, login, make_app


def test_security_headers_are_present_on_every_response(client):
    headers = client.get("/login").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] in {"DENY", "SAMEORIGIN"}
    assert "Referrer-Policy" in headers
    assert "Permissions-Policy" in headers
    assert ("Content-Security-Policy" in headers
            or "Content-Security-Policy-Report-Only" in headers)


def test_content_security_policy_blocks_inline_and_remote_scripts(client):
    response = client.get("/login")
    csp = (response.headers.get("Content-Security-Policy")
           or response.headers.get("Content-Security-Policy-Report-Only"))
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "'unsafe-eval'" not in csp
    script_src = [part for part in csp.split(";") if part.strip().startswith("script-src")]
    assert script_src and "'unsafe-inline'" not in script_src[0]


def test_no_server_banner_is_leaked(client):
    """No header may advertise the framework or its version.

    Werkzeug's default banner is "Werkzeug/<ver> Python/<ver>", which tells an
    attacker exactly which CVEs to try.
    """
    headers = client.get("/login").headers
    assert "X-Powered-By" not in headers
    # The Server banner is emitted by the WSGI server, so the test client
    # never sees one. Whatever is present must not disclose a version.
    banner = headers.get("Server", "")
    for leak in ("werkzeug", "python", "flask", "gunicorn"):
        assert leak not in banner.lower(), f"Server header leaks {leak!r}"


def test_dev_server_suppresses_the_werkzeug_version_banner():
    """run.py must hand werkzeug a request handler with a neutral banner."""
    import inspect

    import run as run_module

    source = inspect.getsource(run_module)
    assert "request_handler=" in source, "app.run must pass a custom request handler"
    assert "version_string" in source, "the handler must override version_string"
    assert '"PhishGuard"' in source


def test_error_pages_do_not_leak_stack_traces(admin_client):
    response = admin_client.get("/campaigns/999999")
    assert response.status_code == 404
    body = response.get_data(as_text=True)
    assert "Traceback" not in body
    assert "sqlalchemy" not in body.lower()
    assert "werkzeug" not in body.lower()


@pytest.mark.parametrize("code,path", [(404, "/nope"), (403, "/audit-logs")])
def test_error_pages_render_a_friendly_document(demo_client, code, path):
    response = demo_client.get(path)
    assert response.status_code == code
    body = response.get_data(as_text=True)
    assert "PhishGuard" in body
    assert "Traceback" not in body


def test_api_errors_are_json_not_html(client):
    response = client.get("/api/campaigns")
    assert response.status_code == 401
    assert response.mimetype == "application/json"
    assert response.get_json()["success"] is False


def test_csrf_token_is_required_for_state_changing_forms(tmp_path):
    """A dedicated app instance re-enables CSRF, which the suite disables."""
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True)
    with app.app_context():
        user = User(username="csrf.admin", email="csrf@cybersafe.edu", role=Role.ADMIN,
                    full_name="CSRF Admin")
        user.set_password(ADMIN_PASSWORD)
        _db.session.add(user)
        _db.session.commit()
    client = app.test_client()
    response = client.post("/login", data={"username": "csrf.admin",
                                           "password": ADMIN_PASSWORD})
    assert response.status_code == 400
    assert "CSRF" in response.get_data(as_text=True).upper()
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


def test_the_login_form_actually_renders_a_csrf_token(tmp_path):
    app = make_app(tmp_path, WTF_CSRF_ENABLED=True)
    body = app.test_client().get("/login").get_data(as_text=True)
    assert 'name="csrf_token"' in body


def test_rate_limiting_blocks_a_login_flood(tmp_path):
    """Flask-Limiter reads RATELIMIT_ENABLED when the extension initialises."""
    app = make_app(tmp_path, RATELIMIT_ENABLED=True, RATELIMIT_LOGIN="3 per minute")
    client = app.test_client()
    statuses = [client.post("/login", data={"username": "ghost", "password": "bad"}).status_code
                for _ in range(6)]
    assert 429 in statuses, statuses
    blocked = client.post("/login", data={"username": "ghost", "password": "bad"})
    assert blocked.status_code == 429
    assert "too many" in blocked.get_data(as_text=True).lower()
    with app.app_context():
        _db.session.remove()
        _db.drop_all()


def test_oversized_request_bodies_are_rejected(app, analyst_client):
    limit = app.config["MAX_CONTENT_LENGTH"]
    response = analyst_client.post("/email-detector", data={
        "sender": "a@b.invalid", "subject": "x", "body": "A" * (limit + 1024),
        "urls": "", "headers": "",
    })
    assert response.status_code == 413


def test_open_redirect_is_not_possible(client, users):
    response = client.post("/login?next=https://evil.example/steal",
                           data={"username": "admin", "password": ADMIN_PASSWORD})
    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]


@pytest.mark.parametrize("payload", ["' OR '1'='1", "admin'--", "admin'; DROP TABLE users;--",
                                     "1 UNION SELECT password_hash FROM users"])
def test_sql_injection_attempt_is_treated_as_data(app, client, users, payload):
    response = client.post("/login", data={"username": payload, "password": payload})
    assert response.status_code == 401
    with app.app_context():
        assert User.query.count() == 4, "the users table must still exist and be intact"


def test_stored_xss_payload_is_escaped_in_the_ui(analyst_client):
    payload = '<script>alert("xss")</script>'
    analyst_client.post("/email-detector", data={
        "sender": "a@b.invalid", "subject": payload,
        "body": "Visit http://example.invalid/x", "urls": "", "headers": "",
    })
    body = analyst_client.get("/email-detector").get_data(as_text=True)
    assert "<script>alert" not in body


def test_reflected_xss_in_url_analysis_is_escaped(analyst_client):
    payload = "<script>alert('xss')</script>"
    response = analyst_client.post("/url-detector",
                                   data={"url": f"http://example.invalid/?q={payload}"},
                                   follow_redirects=True)
    body = response.get_data(as_text=True)
    assert payload not in body
    assert "&lt;script&gt;" in body


def test_audit_log_masks_sensitive_extra_fields(app, users):
    from app.utils.audit import log_audit

    with app.app_context():
        entry = log_audit("LOGIN_SUCCESS", description="test",
                          extra={"password": "hunter2", "api_key": "abc123", "ok": "visible"})
        assert entry.extra["password"] == "[REDACTED]"
        assert entry.extra["api_key"] == "[REDACTED]"
        assert entry.extra["ok"] == "visible"


def test_sensitive_actions_are_written_to_the_audit_trail(app, admin_client, campaign):
    admin_client.post(f"/campaigns/{campaign.id}/status", data={"status": "COMPLETED"},
                      follow_redirects=True)
    with app.app_context():
        actions = {entry.action for entry in AuditLog.query.all()}
    assert AuditAction.LOGIN_SUCCESS in actions
    assert AuditAction.CAMPAIGN_UPDATED in actions


def test_the_required_audit_actions_all_exist():
    required = {"LOGIN_SUCCESS", "LOGIN_FAILURE", "LOGOUT", "CAMPAIGN_CREATED",
                "CAMPAIGN_UPDATED", "ANALYSIS_PERFORMED", "REPORT_GENERATED", "ROLE_CHANGED"}
    available = {value for name, value in vars(AuditAction).items()
                 if name.isupper() and isinstance(value, str)}
    assert required <= available, sorted(required - available)


def test_analysis_actions_are_audited(app, analyst_client):
    analyst_client.post("/url-detector", data={"url": "http://198.51.100.9/verify"})
    with app.app_context():
        actions = {entry.action for entry in AuditLog.query.all()}
    assert AuditAction.ANALYSIS_PERFORMED in actions


def test_audit_log_is_visible_to_admins_only(admin_client, analyst_client, demo_client):
    assert admin_client.get("/audit-logs").status_code == 200
    assert analyst_client.get("/audit-logs").status_code == 403
    assert demo_client.get("/audit-logs").status_code == 403


def test_session_cookie_flags(client, users):
    response = login(client, "admin", ADMIN_PASSWORD)
    cookies = response.headers.getlist("Set-Cookie")
    session_cookie = next((c for c in cookies if c.startswith("phishguard_session")), "")
    assert "HttpOnly" in session_cookie
    assert "SameSite" in session_cookie


def test_production_config_enables_secure_cookies_and_hsts():
    from app.config import ProductionConfig

    assert ProductionConfig.SESSION_COOKIE_SECURE is True
    assert ProductionConfig.SESSION_COOKIE_HTTPONLY is True
    assert ProductionConfig.ENABLE_HSTS is True


def test_production_config_refuses_a_default_secret(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("FLASK_CONFIG", "production")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production")


def test_configuration_check_script_reports_no_failures():
    """Every control the project claims must actually be switched on."""
    app = create_app("testing")
    app.config.update(WTF_CSRF_ENABLED=True)
    assert run_checks(app, verbose=False) == 0


def test_password_hash_is_never_serialised(app, users):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        raw_key = users.admin.api_key

        payload = admin.to_dict()
        assert "password_hash" not in payload
        assert "api_key" not in payload
        assert "api_key_hash" not in payload

        sensitive = admin.to_dict(include_sensitive=True)
        assert "password_hash" not in sensitive
        assert "api_key_hash" not in sensitive
        # The sensitive view identifies the key without disclosing it.
        assert "api_key_prefix" in sensitive
        assert raw_key not in str(sensitive), "serialisation must never emit the raw key"
        assert admin.password_hash not in str(sensitive)


def test_demo_user_cannot_read_another_users_quiz_attempt(app, demo_client, users, quiz):
    from app.models.quiz import AwarenessQuiz
    from app.routes.awareness import grade_quiz

    with app.app_context():
        attempt = grade_quiz(_db.session.get(AwarenessQuiz, quiz.id), {},
                             _db.session.get(User, users.demo2.id))
        attempt_id = attempt.id
    assert demo_client.get(f"/quiz/result/{attempt_id}").status_code == 403


def test_analysis_endpoints_reject_empty_input(analyst_client):
    response = analyst_client.post("/url-detector", data={"url": ""})
    assert response.status_code in (200, 400)
    assert b"analys" in response.data.lower()


def test_secrets_are_not_committed_to_the_repository():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert not (root / ".env").exists(), ".env must never be committed"
    assert (root / ".env.example").exists()
    assert ".env" in (root / ".gitignore").read_text()


def test_sqlite_foreign_keys_are_enforced(app, users, campaign):
    """SQLite ignores FKs unless asked; without this, cascades are untested."""
    with app.app_context():
        result = _db.session.execute(_db.text("PRAGMA foreign_keys")).scalar()
        assert result == 1


def test_production_never_enables_the_werkzeug_debugger():
    """DEBUG must be hard-off in production, not env-controlled.

    The Werkzeug debugger exposes an interactive Python console. Production
    must not be able to switch it on by accident.
    """
    from app.config import ProductionConfig

    assert ProductionConfig.DEBUG is False


def test_flask_debug_env_var_can_disable_the_debugger_in_development(monkeypatch):
    """Regression: DevelopmentConfig.DEBUG used to be hardcoded True.

    That silently ignored ``FLASK_DEBUG=0``, leaving the interactive debugger
    enabled even when an operator had explicitly asked for it to be off - which
    matters as soon as the dev server binds 0.0.0.0 for a demo.
    """
    import importlib

    from app import config as config_module

    monkeypatch.setenv("FLASK_DEBUG", "0")
    importlib.reload(config_module)
    assert config_module.DevelopmentConfig.DEBUG is False

    monkeypatch.setenv("FLASK_DEBUG", "1")
    importlib.reload(config_module)
    assert config_module.DevelopmentConfig.DEBUG is True

    monkeypatch.delenv("FLASK_DEBUG", raising=False)
    importlib.reload(config_module)
    assert config_module.DevelopmentConfig.DEBUG is True


@pytest.mark.parametrize("weak", [
    "",
    "dev-only-insecure-key-change-me",
    "compose-demo-secret-change-me-8f2b41c7a96d",
    "changeme",
    "abcdefghij1234567890",   # 20 chars - under the minimum
    "a" * 64,                 # long but no entropy
])
def test_production_refuses_every_weak_secret(monkeypatch, weak):
    """A predictable SECRET_KEY lets anyone forge a session cookie."""
    monkeypatch.setenv("SECRET_KEY", weak)
    monkeypatch.setenv("FLASK_CONFIG", "production")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app("production")


def test_production_accepts_a_strong_secret(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "kP3nX9vQ2mL8wR4tY7bZ1cF6hJ0sD5gA-eU3iO9pN2xV7qW4")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("FLASK_CONFIG", "production")
    app = create_app("production")
    assert app.config["ENV_NAME"] == "production"
    assert app.config["DEBUG"] is False
