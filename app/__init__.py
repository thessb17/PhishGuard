"""PhishGuard application factory.

PhishGuard is a DEFENSIVE security-awareness platform:

* the simulation subsystem never collects credentials or sensitive data,
* the detection subsystem analyses artefacts offline (nothing is fetched),
* every score is explainable and every privileged action is audited.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFError

from app.config import get_config
from app.extensions import csrf, db, limiter, login_manager, migrate
from app.utils.formatting import register_filters
from app.utils.observability import current_request_id, init_observability
from app.utils.session_policy import log_session_policy, session_diagnostics
from app.utils.security import apply_security_headers

__version__ = "1.0.0"


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    config_class = get_config(config_name)
    app.config.from_object(config_class)
    config_class.init_app(app)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    _configure_logging(app)
    init_observability(app)
    _register_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_hooks(app)
    _register_context(app)

    # Validate that the session cookie can actually reach the browser and
    # back. A mismatched SameSite/Secure policy does not fail loudly - it
    # silently turns every form POST into a CSRF error - so the incoherent
    # combinations are reported here, at startup, in plain language.
    log_session_policy(app)
    _register_cli(app)

    app.logger.info(
        "PhishGuard %s started in %s mode", __version__, app.config.get("ENV_NAME", "unknown")
    )
    return app


# ---------------------------------------------------------------------------
# Wiring helpers
# ---------------------------------------------------------------------------

def _configure_logging(app: Flask) -> None:
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    app.logger.setLevel(level)
    if app.config.get("TESTING"):
        return
    log_file = app.config.get("LOG_FILE")
    if log_file:
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=3)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-8s %(name)s | %(message)s"
            ))
            handler.setLevel(level)
            app.logger.addHandler(handler)
        except OSError:  # pragma: no cover - read-only filesystem
            app.logger.warning("Could not open log file %s", log_file)


def _register_extensions(app: Flask) -> None:
    db.init_app(app)
    migrate.init_app(app, db, directory=str(Path(app.root_path).parent / "migrations"))
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    if app.config.get("RATELIMIT_DEFAULT"):
        limiter.default_limits = [
            lim.strip() for lim in str(app.config["RATELIMIT_DEFAULT"]).split(";") if lim.strip()
        ]
    import app.models  # noqa: F401  (register models with the metadata)


def _register_blueprints(app: Flask) -> None:
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.auth import auth_bp
    from app.routes.awareness import awareness_bp
    from app.routes.campaigns import campaigns_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.email_detector import email_detector_bp
    from app.routes.reports import reports_bp
    from app.routes.simulator import simulator_bp
    from app.routes.url_detector import url_detector_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(campaigns_bp)
    app.register_blueprint(simulator_bp)
    app.register_blueprint(email_detector_bp)
    app.register_blueprint(url_detector_bp)
    app.register_blueprint(awareness_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)  # the API enforces its own CSRF/API-key policy


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] >= accept["text/html"] and accept["application/json"] > 0


#: Canonical machine-readable slugs used by the JSON API.  The global error
#: handlers must emit the *same* envelope as the API blueprint's own helpers,
#: otherwise a client sees ``"code": "not_found"`` for a missing report but
#: ``"code": 404`` for a mistyped path.
ERROR_SLUGS = {
    400: "validation_error",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    413: "payload_too_large",
    429: "rate_limited",
    500: "server_error",
}


def _error_response(code: int, title: str, message: str):
    if _wants_json():
        return jsonify({
            "success": False,
            "data": None,
            "error": {"code": ERROR_SLUGS.get(code, "error"), "message": message,
                      "status": code, "title": title},
            "request_id": current_request_id(),
        }), code
    return render_template("errors/error.html", code=code, title=title, message=message), code


def _csrf_reason_category(description: str) -> str:
    """Map Flask-WTF's description to a stable category for logs/metrics."""
    text = (description or "").lower()
    if "session token is missing" in text:
        return "session_lost"
    if "expired" in text:
        return "expired"
    if "do not match" in text:
        return "mismatch"
    if "missing" in text:
        return "missing"
    if "invalid" in text:
        return "invalid"
    return "other"


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(400)
    def bad_request(error):  # noqa: ANN001
        return _error_response(400, "Bad request",
                               "The request could not be understood or was missing required fields.")

    @app.errorhandler(401)
    def unauthorised(error):  # noqa: ANN001
        return _error_response(401, "Authentication required",
                               "Sign in with a valid account to access this resource.")

    @app.errorhandler(403)
    def forbidden(error):  # noqa: ANN001
        return _error_response(403, "Access denied",
                               "Your role does not grant access to this resource. "
                               "The attempt has been recorded in the audit log.")

    @app.errorhandler(404)
    def not_found(error):  # noqa: ANN001
        return _error_response(404, "Not found", "The requested resource does not exist.")

    @app.errorhandler(405)
    def method_not_allowed(error):  # noqa: ANN001
        return _error_response(405, "Method not allowed",
                               "That HTTP method is not supported on this endpoint.")

    @app.errorhandler(413)
    def too_large(error):  # noqa: ANN001
        return _error_response(413, "Payload too large",
                               "The submitted content exceeds the configured size limit.")

    @app.errorhandler(429)
    def rate_limited(error):  # noqa: ANN001
        return _error_response(429, "Too many requests",
                               "Rate limit exceeded. Wait a moment before trying again.")

    @app.errorhandler(500)
    def server_error(error):  # noqa: ANN001
        db.session.rollback()
        app.logger.exception("Unhandled server error")
        return _error_response(500, "Internal server error",
                               "Something went wrong. The incident has been logged.")

    @app.errorhandler(CSRFError)
    def csrf_error(error):  # noqa: ANN001
        # Diagnose every CSRF rejection. Presence booleans only - never the
        # token, the session contents, or any secret. This is what turns
        # "CSRF validation failed" into an actionable report: the common
        # cause is a MISSING session cookie, not a bad token.
        try:
            from flask import session as _session

            from app.utils.session_policy import session_diagnostics

            d = session_diagnostics(request, _session, app.config)
            logging.getLogger("phishguard.security").warning(
                "csrf.rejected", extra={
                    "event": "security", "action": "csrf_rejected",
                    "outcome": "REJECTED", "actor": None,
                    "resource": request.path,
                    "ip": request.remote_addr,
                    "method": request.method,
                    "path": request.path,
                    "extra_fields": {
                        "endpoint": request.endpoint,
                        "content_type": (request.content_type or "")[:64],
                        "session_cookie": "PRESENT" if d["session_cookie_present"] else "MISSING",
                        "csrf_session": "PRESENT" if d["csrf_session_present"] else "MISSING",
                        "csrf_form": "PRESENT" if d["csrf_form_present"] else "MISSING",
                        "csrf_header": "PRESENT" if d["csrf_header_present"] else "MISSING",
                        "scheme": request.scheme,
                        "host": request.host,
                        "origin": request.headers.get("Origin", "-")[:80],
                        "referer": request.headers.get("Referer", "-")[:80],
                        "secure_cookie": d["session_cookie_secure"],
                        "samesite": d["session_cookie_samesite"],
                        "reason": str(getattr(error, "description", ""))[:120],
                        # Category, not the token. Flask-WTF distinguishes
                        # these and they point at different causes:
                        #   missing      -> form/header never sent one
                        #   session_lost -> cookie did not arrive (SameSite,
                        #                   Secure-over-HTTP, blocked cookies)
                        #   expired      -> page open past WTF_CSRF_TIME_LIMIT
                        #   invalid      -> malformed or foreign token
                        "reason_category": _csrf_reason_category(
                            str(getattr(error, "description", ""))),
                    },
                })
        except Exception:  # noqa: BLE001 - diagnostics must never mask the 400
            pass
        """Explain a CSRF rejection without leaking anything.

        The token is still rejected - this only replaces an unhelpful
        message with the actual likely causes and a recovery path.
        """
        if _wants_json():
            return jsonify({
                "success": False,
                "data": None,
                "error": {
                    "code": "csrf_required",
                    "message": "A valid CSRF token is required.",
                    "status": 400,
                    "title": "CSRF validation failed",
                },
                "request_id": current_request_id(),
            }), 400
        return render_template(
            "errors/csrf.html",
            code=400,
            title="CSRF validation failed",
            reset_available=app.config.get("ENV_NAME") != "production",
        ), 400


def _register_hooks(app: Flask) -> None:
    @app.after_request
    def _headers(response):  # noqa: ANN001
        return apply_security_headers(response, app.config)

    # Opt-in diagnostics for debugging cookie/CSRF delivery locally.
    # Never enabled in production, and emits presence booleans only - no
    # token, no session contents, no secret.
    # Development-only request trace: "METHOD PATH STATUS" for every request.
    # Makes an unexpected unsafe request (e.g. POST /) immediately visible.
    # Automatically off in production, and logs no body, token, or cookie.
    if app.config.get("REQUEST_TRACE") and app.config.get("ENV_NAME") != "production":
        @app.after_request
        def _trace(response):  # noqa: ANN001
            app.logger.info("TRACE %s %s %s", request.method, request.full_path.rstrip("?"),
                            response.status_code)
            return response

    if app.config.get("CSRF_DEBUG") and app.config.get("ENV_NAME") != "production":
        @app.before_request
        def _csrf_diagnostics():  # noqa: ANN001
            from flask import session as _session

            info = session_diagnostics(request, _session, app.config)
            app.logger.info("[csrf-debug] " + " ".join(
                f"{k.upper()}={v}" for k, v in info.items()))

    @app.before_request
    def _session_hardening():
        from flask import session

        session.permanent = True

    @login_manager.unauthorized_handler
    def _unauthorized():
        from flask import flash, redirect, url_for

        if _wants_json():
            return jsonify({
                "success": False,
                "error": {"code": "unauthorized", "message": "Authentication required."},
            }), 401
        flash("Please sign in to continue.", "warning")
        return redirect(url_for("auth.login", next=request.path))


def _register_context(app: Flask) -> None:
    register_filters(app)

    @app.context_processor
    def _inject_globals():
        from datetime import datetime

        from app.models.simulation import EventType

        return {
            "APP_NAME": app.config.get("APP_NAME", "PhishGuard"),
            "APP_TAGLINE": app.config.get("APP_TAGLINE", ""),
            "PROJECT_OWNER": app.config.get("PROJECT_OWNER", "Sabyasachi Bhowmik"),
            "INSTITUTION": app.config.get("INSTITUTION", "Andhra University"),
            "DEPARTMENT": app.config.get("DEPARTMENT", "Department of Computer Science and Systems Engineering"),
            "PROJECT_CREDIT": app.config.get("PROJECT_CREDIT", "Developed by Sabyasachi Bhowmik · Andhra University"),
            "APP_VERSION": __version__,
            "SIMULATION_BANNER": app.config.get("SIMULATION_BANNER", ""),
            "current_year": datetime.now().year,
            "EventType": EventType,
        }

    @app.shell_context_processor
    def _shell_context():
        import app.models as models

        return {"db": db, "models": models, **{name: getattr(models, name) for name in models.__all__}}


def _register_cli(app: Flask) -> None:
    import click

    @app.cli.command("init-db")
    def init_db():
        """Create all database tables."""
        db.create_all()
        click.echo("Database tables created.")

    @app.cli.command("seed-db")
    @click.option("--reset", is_flag=True, help="Drop existing tables first.")
    def seed_db(reset):
        """Populate the database with fictional demo data."""
        from scripts.seed_database import seed

        seed(reset=reset)
        click.echo("Demo data seeded.")

    @app.cli.command("security-check")
    def security_check():
        """Run the built-in security configuration checklist."""
        from scripts.security_check import run_checks

        failures = run_checks(app)
        raise SystemExit(1 if failures else 0)
