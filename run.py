#!/usr/bin/env python3
"""PhishGuard entry point.

Development::

    python run.py

Production (example)::

    gunicorn --bind 0.0.0.0:8000 "run:app"

The configuration profile is chosen with the ``FLASK_CONFIG`` environment
variable (``development``, ``testing``, ``production``); values are read from a
``.env`` file when one is present. No secret is ever hardcoded here.
"""

from __future__ import annotations

import os
import sys


def _fail(title: str, lines: list[str]) -> "None":
    """Print an actionable message instead of a bare traceback."""
    bar = "=" * 70
    print(bar, file=sys.stderr)
    print(f"  PhishGuard cannot start: {title}", file=sys.stderr)
    print(bar, file=sys.stderr)
    for line in lines:
        print(f"  {line}", file=sys.stderr)
    print(bar, file=sys.stderr)
    sys.exit(1)


try:
    from app import create_app
except ModuleNotFoundError as exc:          # dependencies not installed
    _fail(
        f"a required package is missing ({exc.name}).",
        [
            "Install the dependencies, then start again:",
            "",
            "    python -m venv venv",
            "    source venv/bin/activate      # Windows: venv\\Scripts\\activate",
            "    pip install -r requirements.txt",
            "",
            "Or let the setup script do all of it, including starting the server:",
            "",
            "    python scripts/setup.py --run",
        ],
    )

app = create_app(os.environ.get("FLASK_CONFIG"))


def _guard_cookie_policy(application) -> None:
    """Refuse to serve plain HTTP with Secure session cookies.

    `run.py` is the development server: it speaks **plain HTTP**. A browser
    will store a cookie marked ``Secure`` and then never send it back over
    HTTP, so the session silently disappears and every form POST fails with
    "CSRF validation failed" - blaming CSRF for a cookie-transport problem.

    This exact mistake shipped once already. Failing loudly here is the only
    way to make it impossible to repeat: the misconfiguration is invisible
    from the server side, and nearly impossible to diagnose from the browser.

    Production is unaffected - it is served by gunicorn behind TLS, not by
    this entry point, and ProductionConfig keeps SESSION_COOKIE_SECURE=True.
    """
    if application.config.get("ENV_NAME") == "production":
        return
    if not application.config.get("SESSION_COOKIE_SECURE"):
        return
    if os.environ.get("ALLOW_SECURE_COOKIE_OVER_HTTP", "").strip() in ("1", "true", "yes"):
        print("  NOTE: Secure session cookie allowed over HTTP by explicit override.")
        print("        Only correct if TLS terminates in front of this process.")
        return
    _fail(
        "SESSION_COOKIE_SECURE=1 with the plain-HTTP development server.",
        [
            "A browser will NOT return a Secure cookie over http://, so the",
            "session is lost on every request and all form submissions fail",
            "with 'CSRF validation failed'.",
            "",
            "For local development (http://localhost:5000) use:",
            "    SESSION_COOKIE_SECURE=0",
            "    SESSION_COOKIE_SAMESITE=Lax",
            "",
            "Secure cookies require HTTPS. Serve production behind TLS with:",
            "    gunicorn --bind 0.0.0.0:8000 'run:app'",
            "",
            "Override this guard only if TLS terminates in front of this",
            "process:  ALLOW_SECURE_COOKIE_OVER_HTTP=1",
        ],
    )


def _ensure_initialised(application) -> None:
    """Create and seed the database on first run.

    A fresh clone has no database, so `python run.py` previously started a
    server where every login failed. Rather than make the operator discover
    the separate seeding step from a login failure, the first run creates the
    schema and loads the demo data, announcing exactly what it did.

    Existing data is never touched: if any user already exists, this is a
    no-op. Disable entirely with AUTO_INIT_DB=0.
    """
    if os.environ.get("AUTO_INIT_DB", "1").strip().lower() in ("0", "false", "no"):
        return
    # Production must not silently create demo accounts.
    if application.config.get("ENV_NAME") == "production":
        return

    from sqlalchemy import inspect as _inspect

    from app.extensions import db

    with application.app_context():
        try:
            has_users = _inspect(db.engine).has_table("users")
            if has_users:
                from app.models.user import User

                if db.session.query(User.id).first() is not None:
                    return          # already initialised - leave it alone
        except Exception:           # noqa: BLE001 - fall through to creation
            has_users = False

        print("  First run detected - creating and seeding the database...")
        db.create_all()

    try:
        from scripts.seed_database import seed

        seed(reset=False, verbose=False)
        print("  Demo data loaded. Demo accounts: admin, analyst, priya.demo")
        print("  Passwords are printed by: python scripts/seed_database.py")
    except Exception as exc:        # noqa: BLE001 - never block startup
        print(f"  Could not seed demo data ({type(exc).__name__}: {exc}).")
        print("  Run it manually:  python scripts/seed_database.py")


def _pick_host(requested: str | None) -> tuple[str, bool]:
    """Resolve the bind address, preferring dual-stack.

    Default is ``::`` rather than ``0.0.0.0``. On this and most Linux hosts
    ``localhost`` resolves to the IPv6 loopback ``::1`` *first*; a socket bound
    to ``0.0.0.0`` is IPv4-only, so ``http://localhost:5000`` gets connection
    refused on its first attempt even though ``127.0.0.1:5000`` works. Clients
    that do not retry over IPv4 simply fail. Binding ``::`` serves both
    families from one socket, so both hostnames behave identically.

    Falls back to ``0.0.0.0`` where IPv6 is unavailable.
    """
    import socket

    if requested:
        return requested, False
    if not socket.has_ipv6:
        return "0.0.0.0", False
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            probe.bind(("::", 0))
            return "::", True
        finally:
            probe.close()
    except OSError:
        return "0.0.0.0", False


def _port_available(host: str, port: int) -> tuple[bool, str]:
    """Report whether the port is free, without killing anything."""
    import socket

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    probe = socket.socket(family, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        try:
            probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
    try:
        probe.bind((host, port))
        return True, ""
    except OSError as exc:
        owner = ""
        try:  # best effort - never required
            import subprocess

            out = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True,
                                 timeout=5).stdout
            for line in out.splitlines():
                if f":{port} " in line and "pid=" in line:
                    owner = line.strip()
                    break
        except Exception:  # noqa: BLE001
            owner = ""
        return False, owner or str(exc)
    finally:
        probe.close()


def _preflight(application) -> list[tuple[str, str, str]]:
    """Fast startup checks. Returns (level, label, detail) rows."""
    import importlib.util
    from pathlib import Path as _Path

    rows: list[tuple[str, str, str]] = []

    major, minor = sys.version_info[:2]
    rows.append(("PASS" if (major, minor) >= (3, 11) else "WARN",
                 "Python version", f"{major}.{minor} (3.11+ expected)"))

    missing = [m for m in ("flask", "flask_sqlalchemy", "flask_wtf", "sqlalchemy",
                           "sklearn", "joblib") if importlib.util.find_spec(m) is None]
    rows.append(("PASS" if not missing else "FAIL", "Dependencies",
                 "all present" if not missing
                 else f"missing {', '.join(missing)} -> pip install -r requirements.txt"))

    rows.append(("PASS", "Configuration",
                 f"{application.config.get('ENV_NAME')} profile loaded"))

    # Database: reachable and populated?
    try:
        from sqlalchemy import inspect as _inspect

        from app.extensions import db as _db

        with application.app_context():
            tables = _inspect(_db.engine).get_table_names()
        if not tables:
            rows.append(("WARN", "Database",
                         "no tables yet -> python scripts/seed_database.py"))
        else:
            rows.append(("PASS", "Database", f"{len(tables)} tables"))
    except Exception as exc:  # noqa: BLE001
        rows.append(("FAIL", "Database",
                     f"{type(exc).__name__} -> python scripts/seed_database.py"))

    # ML artefact: present and loadable, without retraining.
    try:
        from app.ml.predict import DEFAULT_MODEL_PATH, model_available

        if not _Path(DEFAULT_MODEL_PATH).exists():
            rows.append(("WARN", "ML model",
                         "artifact missing -> python train.py"))
        elif model_available():
            rows.append(("PASS", "ML model", "loaded from app/ml/model.joblib"))
        else:
            rows.append(("WARN", "ML model",
                         "present but not loadable -> python train.py"))
    except Exception as exc:  # noqa: BLE001
        rows.append(("WARN", "ML model", f"{type(exc).__name__} -> python train.py"))

    root = _Path(__file__).resolve().parent
    for label, rel in (("Templates", "app/templates/base.html"),
                       ("Static files", "app/static/css/phishguard.css"),
                       ("Dataset", "data/datasets/url_dataset.csv")):
        target = root / rel
        rows.append(("PASS" if target.exists() else "WARN", label,
                     rel if target.exists() else f"{rel} missing"))

    return rows


if __name__ == "__main__":
    requested = os.environ.get("HOST")
    host, dual_stack = _pick_host(requested)
    port = int(os.environ.get("PORT", "5000"))
    debug = app.config.get("DEBUG", False)

    # Never expose the interactive Werkzeug debugger on a non-loopback bind.
    # The debugger offers an arbitrary-code console; on 0.0.0.0 or :: that is
    # reachable from the network. Explicit FLASK_DEBUG=1 is still honoured on
    # loopback only.
    public_bind = host not in ("127.0.0.1", "localhost", "::1")
    if debug and public_bind:
        debug = False
        print("  NOTE: debugger disabled because the server is bound to "
              f"{host} (not loopback).")

    _guard_cookie_policy(app)

    checks = _preflight(app)
    failures = [r for r in checks if r[0] == "FAIL"]

    print("=" * 60)
    print("PhishGuard")
    print("Phishing Attack Simulation and Detection Platform")
    print("=" * 60)
    print()
    print(f"Environment : {app.config['ENV_NAME']}")
    print(f"Host        : {host}{' (dual-stack IPv4 + IPv6)' if dual_stack else ''}")
    print(f"Port        : {port}")
    for level, label, detail in checks:
        print(f"{label:<12}: {level:<4} {detail}")
    print(f"{'CSRF':<12}: {'ENABLED' if app.config.get('WTF_CSRF_ENABLED') else 'DISABLED'}")
    print(f"{'Debug':<12}: {'ON' if debug else 'OFF'}")
    print()

    if failures:
        print("Startup blocked:")
        for _, label, detail in failures:
            print(f"  [FAIL] {label}: {detail}")
        sys.exit(1)

    free, owner = _port_available(host, port)
    if not free:
        print(f"Port {port} is already in use.")
        if owner:
            print(f"  {owner}")
        print(f"  Start on another port:  PORT={port + 1} python run.py")
        sys.exit(1)

    _ensure_initialised(app)

    print("Local URLs:")
    print(f"  http://localhost:{port}/")
    print(f"  http://127.0.0.1:{port}/")
    print(f"  http://localhost:{port}/health")
    print()
    print("Demo accounts: admin, analyst, priya.demo")
    print("  (passwords are printed by scripts/seed_database.py, never here)")
    print("=" * 60)

    # Werkzeug's default banner is "Werkzeug/<ver> Python/<ver>", which tells
    # anyone scanning the host exactly which versions to look up CVEs for.
    from werkzeug.serving import WSGIRequestHandler

    class QuietRequestHandler(WSGIRequestHandler):
        def version_string(self) -> str:  # noqa: D401 - overrides stdlib
            return "PhishGuard"

    app.run(host=host, port=port, debug=debug, use_reloader=debug,
            request_handler=QuietRequestHandler)
