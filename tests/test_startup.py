"""Startup and reachability regression tests.

Pins the 2026-10-01 startup fix. Two problems were reported as "not reachable
at http://localhost:5000":

1. ``run.py`` defaulted to ``HOST=127.0.0.1``, so nothing outside the machine
   (or outside the container's loopback) could reach it;
2. once bound to ``0.0.0.0`` it was **IPv4-only**, while ``localhost``
   resolves to the IPv6 loopback ``::1`` first on this and most Linux hosts.
   ``127.0.0.1:5000`` worked and ``localhost:5000`` was refused.

These tests need no running server.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from app import create_app

ROOT = Path(__file__).resolve().parents[1]


# --- application factory ----------------------------------------------------

def test_create_app_testing_builds():
    app = create_app("testing")
    assert app.config["ENV_NAME"] == "testing"


def test_run_module_exposes_an_app_with_routes():
    import run

    assert run.app is not None
    assert len(list(run.app.url_map.iter_rules())) > 20


def test_extensions_are_initialised_once():
    from app.extensions import csrf, db, limiter, login_manager

    app = create_app("testing")
    assert app.extensions.get("csrf") is csrf
    assert app.extensions.get("sqlalchemy") is not None
    # Flask-SQLAlchemy 3.x binds per-app via init_app; the engine resolves
    # only inside an application context.
    with app.app_context():
        assert db.engine is not None
    assert login_manager is not None and limiter is not None


def test_blueprints_are_registered_exactly_once():
    app = create_app("testing")
    names = list(app.blueprints)
    assert len(names) == len(set(names)), "a blueprint was registered twice"
    for required in ("auth", "dashboard", "campaigns", "api", "url_detector",
                     "email_detector", "reports", "simulator", "awareness", "admin"):
        assert required in app.blueprints, f"missing blueprint: {required}"


# --- routes -----------------------------------------------------------------

@pytest.mark.parametrize("rule", [
    "/", "/login", "/logout", "/dashboard", "/campaigns", "/simulator",
    "/email-detector", "/url-detector", "/awareness", "/reports",
    "/audit-logs", "/profile", "/health", "/api/health",
])
def test_expected_routes_are_registered(rule):
    app = create_app("testing")
    assert rule in {str(r) for r in app.url_map.iter_rules()}, f"{rule} not registered"


def test_root_redirects_anonymous_users_to_login():
    app = create_app("testing")
    response = app.test_client().get("/")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_root_is_get_only_and_needs_no_csrf():
    app = create_app("testing")
    rule = next(r for r in app.url_map.iter_rules() if str(r) == "/")
    assert "POST" not in rule.methods
    assert app.test_client().post("/").status_code == 405


# --- /health ----------------------------------------------------------------

def test_health_requires_no_authentication():
    response = create_app("testing").test_client().get("/health")
    assert response.status_code == 200


def test_health_reports_the_documented_shape():
    body = create_app("testing").test_client().get("/health").get_json()
    for key in ("status", "service", "version", "database", "ml"):
        assert key in body, f"/health missing {key}"
    assert body["status"] in ("ok", "degraded")


def test_health_leaks_no_secrets_or_paths():
    app = create_app("testing")
    raw = app.test_client().get("/health").get_data(as_text=True)
    assert app.config["SECRET_KEY"] not in raw
    assert app.config["SQLALCHEMY_DATABASE_URI"] not in raw
    for marker in ("/home/", "password", "api_key", "csrf"):
        assert marker not in raw.lower()


def test_health_is_not_cached():
    response = create_app("testing").test_client().get("/health")
    assert "no-store" in response.headers.get("Cache-Control", "")


def test_health_reports_degraded_when_the_database_is_unreachable(monkeypatch):
    """A broken component must surface as 503, not a cheerful 200."""
    app = create_app("testing")

    from app.extensions import db

    def _boom(*_args, **_kwargs):
        raise RuntimeError("database down")

    monkeypatch.setattr(db.session, "execute", _boom)
    response = app.test_client().get("/health")
    assert response.status_code == 503
    body = response.get_json()
    assert body["status"] == "degraded"
    assert body["database"] == "error"
    assert "database down" not in response.get_data(as_text=True)


# --- host / port resolution -------------------------------------------------

def test_default_host_is_not_loopback_only():
    """The reported bug: the default bind was 127.0.0.1."""
    import run

    host, _ = run._pick_host(None)
    assert host in ("::", "0.0.0.0"), f"default host {host!r} is loopback-only"


def test_default_host_prefers_dual_stack_when_ipv6_exists():
    import run

    host, dual = run._pick_host(None)
    if socket.has_ipv6:
        assert host == "::" and dual is True, (
            "localhost resolves to ::1 first; an IPv4-only bind refuses it")
    else:
        assert host == "0.0.0.0"


def test_explicit_host_is_respected():
    import run

    assert run._pick_host("127.0.0.1")[0] == "127.0.0.1"
    assert run._pick_host("0.0.0.0")[0] == "0.0.0.0"


def test_port_availability_probe_detects_a_busy_port():
    import run

    held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    held.bind(("127.0.0.1", 0))
    held.listen(1)
    port = held.getsockname()[1]
    try:
        free, _ = run._port_available("127.0.0.1", port)
        assert free is False
    finally:
        held.close()
    free, _ = run._port_available("127.0.0.1", port)
    assert free is True


# --- safe defaults ----------------------------------------------------------

def test_debugger_is_never_enabled_on_a_public_bind():
    """The Werkzeug debugger is an arbitrary-code console."""
    source = (ROOT / "run.py").read_text(encoding="utf-8")
    assert "public_bind" in source
    assert "debugger disabled" in source


def test_production_never_enables_debug():
    from app.config import ProductionConfig

    assert ProductionConfig.DEBUG is False


def test_csrf_is_enabled_in_development():
    app = create_app("development")
    assert app.config["WTF_CSRF_ENABLED"] is True
    from app.extensions import csrf

    assert app.extensions.get("csrf") is csrf


def test_development_cookie_policy_suits_plain_http():
    app = create_app("development")
    assert app.config["SESSION_COOKIE_SECURE"] is False
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"


# --- preflight diagnostics --------------------------------------------------

def test_preflight_reports_every_component():
    import run

    rows = run._preflight(create_app("testing"))
    labels = {label for _, label, _ in rows}
    for expected in ("Python version", "Dependencies", "Configuration",
                     "Database", "ML model", "Templates", "Static files"):
        assert expected in labels, f"preflight missing {expected}"
    assert all(level in ("PASS", "WARN", "FAIL") for level, _, _ in rows)


def test_preflight_leaks_no_secrets():
    import run

    app = create_app("testing")
    blob = str(run._preflight(app))
    assert app.config["SECRET_KEY"] not in blob


def test_startup_banner_does_not_print_passwords():
    source = (ROOT / "run.py").read_text(encoding="utf-8")
    for secret in ("Admin@Phish2026", "Analyst@Phish2026", "Demo@Phish2026"):
        assert secret not in source, f"{secret} must never appear in startup output"


# --- database initialisation ------------------------------------------------

def test_database_initialises_from_zero(tmp_path):
    from tests.conftest import make_app

    app = make_app(tmp_path)
    from sqlalchemy import inspect

    from app.extensions import db

    with app.app_context():
        tables = inspect(db.engine).get_table_names()
    assert len(tables) >= 10, f"expected the full schema, got {tables}"


# --- smoke test script ------------------------------------------------------

def test_smoke_test_script_exists_and_compiles():
    script = ROOT / "scripts" / "smoke_test.py"
    assert script.exists()
    compile(script.read_text(encoding="utf-8"), str(script), "exec")


def test_smoke_test_fails_cleanly_when_the_server_is_down():
    proc = subprocess.run(
        [sys.executable, "scripts/smoke_test.py", "--base-url", "http://127.0.0.1:1"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert proc.returncode != 0, "a down server must not report success"
    assert "Traceback" not in proc.stderr
    assert "unreachable" in proc.stderr.lower()
