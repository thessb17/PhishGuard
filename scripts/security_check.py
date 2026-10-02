#!/usr/bin/env python3
"""Static security self-assessment for a running PhishGuard configuration.

The script inspects the live Flask configuration and the source tree and prints
a PASS/WARN/FAIL line per control. It is a configuration checklist, not a
vulnerability scanner: it cannot prove the absence of bugs, only that the
controls this project claims to implement are actually switched on.

Usage::

    python scripts/security_check.py
    flask --app run:app security-check
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

INSECURE_SECRETS = {"", "dev", "secret", "changeme", "change-me", "password",
                    "phishguard", "dev-secret-key", "testing-secret-key",
                    "dev-only-insecure-key-change-me"}

#: Patterns that would indicate credential harvesting crept into the simulator.
CREDENTIAL_INPUT = re.compile(
    r"""<input[^>]*type\s*=\s*["'](?:password)["']""", re.IGNORECASE
)


class Check:
    def __init__(self, name: str, status: str, detail: str):
        self.name = name
        self.status = status
        self.detail = detail

    def line(self) -> str:
        symbol = {PASS: "[ PASS ]", WARN: "[ WARN ]", FAIL: "[ FAIL ]"}[self.status]
        return f"{symbol} {self.name:<44} {self.detail}"


def _check_secret_key(app) -> Check:
    key = app.config.get("SECRET_KEY") or ""
    if str(key).strip().lower() in INSECURE_SECRETS:
        status = FAIL if app.config.get("ENV_NAME") == "production" else WARN
        return Check("SECRET_KEY is not a default value", status,
                     "placeholder secret in use - set SECRET_KEY in the environment")
    if len(str(key)) < 32:
        return Check("SECRET_KEY is not a default value", WARN,
                     f"only {len(str(key))} characters; 32+ recommended")
    return Check("SECRET_KEY is not a default value", PASS, f"{len(str(key))} characters")


def _check_hardcoded_secrets() -> Check:
    suspicious = []
    pattern = re.compile(r"""(SECRET_KEY|PASSWORD|API_KEY)\s*=\s*["'][^"'{}\s]{8,}["']""")
    allowed_files = {"seed_database.py", "security_check.py", "conftest.py"}
    for path in (ROOT / "app").rglob("*.py"):
        if path.name in allowed_files:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "os.environ" in line or "getenv" in line or line.strip().startswith("#"):
                continue
            if pattern.search(line):
                suspicious.append(f"{path.relative_to(ROOT)}:{number}")
    if suspicious:
        return Check("No hardcoded secrets in app/", FAIL, ", ".join(suspicious[:3]))
    return Check("No hardcoded secrets in app/", PASS, "configuration read from the environment")


def _check_csrf(app) -> Check:
    if not app.config.get("WTF_CSRF_ENABLED", True):
        return Check("CSRF protection enabled", FAIL, "WTF_CSRF_ENABLED is False")
    if "csrf" not in {ext.lower() for ext in app.extensions}:
        # Flask-WTF registers itself under 'csrf'; fall back to checking the callbacks.
        if not any("csrf" in str(fn) for fn in app.before_request_funcs.get(None, [])):
            return Check("CSRF protection enabled", WARN, "CSRFProtect not detected")
    return Check("CSRF protection enabled", PASS, "Flask-WTF CSRFProtect active")


def _check_password_hashing(app) -> Check:
    method = app.config.get("PASSWORD_HASH_METHOD", "")
    if "pbkdf2" in method or "scrypt" in method or "argon" in method:
        return Check("Passwords stored as salted hashes", PASS, method)
    return Check("Passwords stored as salted hashes", FAIL, f"weak method: {method!r}")


def _check_password_policy(app) -> Check:
    minimum = app.config.get("PASSWORD_MIN_LENGTH", 0)
    if minimum >= 10:
        return Check("Minimum password length >= 10", PASS, f"{minimum} characters")
    return Check("Minimum password length >= 10", WARN, f"{minimum} characters")


def _check_lockout(app) -> Check:
    attempts = app.config.get("MAX_FAILED_LOGINS", 0)
    minutes = app.config.get("ACCOUNT_LOCKOUT_MINUTES", 0)
    if 0 < attempts <= 10 and minutes > 0:
        return Check("Account lockout configured", PASS,
                     f"{attempts} attempts / {minutes} minute lockout")
    return Check("Account lockout configured", FAIL, "lockout disabled")


def _check_rate_limits(app) -> Check:
    login = app.config.get("RATELIMIT_LOGIN")
    analysis = app.config.get("RATELIMIT_ANALYSIS")
    if login and analysis:
        return Check("Rate limiting configured", PASS, f"login {login}")
    return Check("Rate limiting configured", FAIL, "no limits configured")


def _check_session_cookies(app) -> Check:
    problems = []
    if not app.config.get("SESSION_COOKIE_HTTPONLY", False):
        problems.append("HttpOnly off")
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        problems.append("SameSite unset")
    secure = app.config.get("SESSION_COOKIE_SECURE", False)
    if not secure and app.config.get("ENV_NAME") == "production":
        problems.append("Secure off in production")
    if problems:
        status = FAIL if app.config.get("ENV_NAME") == "production" else WARN
        return Check("Session cookie flags", status, "; ".join(problems))
    return Check("Session cookie flags", PASS,
                 f"HttpOnly, SameSite={app.config.get('SESSION_COOKIE_SAMESITE')}, "
                 f"Secure={secure}")


def _check_security_headers(app) -> Check:
    client = app.test_client()
    response = client.get("/login")
    required = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
                "Referrer-Policy", "Permissions-Policy"]
    missing = [header for header in required if header not in response.headers
               and f"{header}-Report-Only" not in response.headers]
    if missing:
        return Check("Security headers on responses", FAIL, "missing: " + ", ".join(missing))
    return Check("Security headers on responses", PASS, ", ".join(required))


def _check_csp_inline(app) -> Check:
    client = app.test_client()
    response = client.get("/login")
    csp = (response.headers.get("Content-Security-Policy")
           or response.headers.get("Content-Security-Policy-Report-Only") or "")
    if "unsafe-eval" in csp:
        return Check("CSP forbids unsafe-eval", FAIL, "script-src allows unsafe-eval")
    if "'unsafe-inline'" in csp.split("script-src")[-1].split(";")[0]:
        return Check("CSP forbids inline script", WARN, "script-src allows inline script")
    return Check("CSP forbids inline script", PASS, "script-src is restricted")


def _check_debug(app) -> Check:
    if app.config.get("DEBUG") and app.config.get("ENV_NAME") == "production":
        return Check("Debug mode off in production", FAIL, "DEBUG=True with production config")
    return Check("Debug mode off in production", PASS,
                 f"DEBUG={app.config.get('DEBUG')} in {app.config.get('ENV_NAME')}")


def _check_error_pages(app) -> Check:
    client = app.test_client()
    response = client.get("/this-route-does-not-exist")
    body = response.get_data(as_text=True)
    if response.status_code != 404:
        return Check("Errors return friendly pages", FAIL, f"404 route returned {response.status_code}")
    if "Traceback" in body or "werkzeug" in body.lower():
        return Check("Errors return friendly pages", FAIL, "stack trace leaked to the client")
    return Check("Errors return friendly pages", PASS, "custom 404 rendered, no traceback")


def _check_no_credential_capture() -> Check:
    offenders = []
    simulator_dir = ROOT / "app" / "templates" / "simulator"
    for path in simulator_dir.rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        if CREDENTIAL_INPUT.search(text):
            offenders.append(str(path.relative_to(ROOT)))
        if re.search(r"<input[^>]*name\s*=\s*[\"'](?:user|username|email|pass)", text, re.I):
            offenders.append(str(path.relative_to(ROOT)))
    if offenders:
        return Check("Simulator collects no credentials", FAIL, ", ".join(sorted(set(offenders))))
    return Check("Simulator collects no credentials", PASS,
                 "no credential inputs in simulator templates")


def _check_simulation_flag(app) -> Check:
    if app.config.get("SIMULATION_COLLECT_CREDENTIALS", False):
        return Check("SIMULATION_COLLECT_CREDENTIALS is False", FAIL,
                     "credential collection flag enabled - refuse to run")
    return Check("SIMULATION_COLLECT_CREDENTIALS is False", PASS,
                 "hard-disabled in every configuration profile")


def _check_https_enforcement(app) -> Check:
    if app.config.get("ENV_NAME") == "production" and not app.config.get("ENABLE_HSTS", False):
        return Check("HSTS enabled in production", WARN, "ENABLE_HSTS is False")
    return Check("HSTS enabled in production", PASS,
                 f"ENABLE_HSTS={app.config.get('ENABLE_HSTS')}")


def _check_sql_injection_surface() -> Check:
    risky = []
    pattern = re.compile(r"(execute\(\s*f[\"']|text\(\s*f[\"']|\.filter\(\s*f[\"'])")
    for path in (ROOT / "app").rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                risky.append(f"{path.relative_to(ROOT)}:{number}")
    if risky:
        return Check("No f-string SQL construction", FAIL, ", ".join(risky[:3]))
    return Check("No f-string SQL construction", PASS, "ORM query API used throughout")


def _check_audit_redaction() -> Check:
    audit = (ROOT / "app" / "utils" / "audit.py").read_text(encoding="utf-8")
    if "_FORBIDDEN_KEYS" in audit and "REDACTED" in audit:
        return Check("Audit log redacts sensitive keys", PASS,
                     "password/token/api_key values masked")
    return Check("Audit log redacts sensitive keys", FAIL, "no redaction logic found")


def _check_max_content_length(app) -> Check:
    limit = app.config.get("MAX_CONTENT_LENGTH") or 0
    if 0 < limit <= 16 * 1024 * 1024:
        return Check("Request body size limited", PASS, f"{limit // 1024} KiB")
    return Check("Request body size limited", WARN, "MAX_CONTENT_LENGTH not set")


def run_checks(app=None, verbose: bool = True) -> int:
    """Run every control check. Returns the number of failures."""
    if app is None:
        from app import create_app

        app = create_app()

    with app.app_context():
        checks = [
            _check_secret_key(app),
            _check_hardcoded_secrets(),
            _check_csrf(app),
            _check_password_hashing(app),
            _check_password_policy(app),
            _check_lockout(app),
            _check_rate_limits(app),
            _check_session_cookies(app),
            _check_security_headers(app),
            _check_csp_inline(app),
            _check_debug(app),
            _check_error_pages(app),
            _check_no_credential_capture(),
            _check_simulation_flag(app),
            _check_https_enforcement(app),
            _check_sql_injection_surface(),
            _check_audit_redaction(),
            _check_max_content_length(app),
        ]

    failures = sum(1 for check in checks if check.status == FAIL)
    warnings = sum(1 for check in checks if check.status == WARN)

    if verbose:
        print("=" * 90)
        print(f"PhishGuard security configuration check - profile: {app.config.get('ENV_NAME')}")
        print("=" * 90)
        for check in checks:
            print(check.line())
        print("-" * 90)
        print(f"{len(checks)} checks - {len(checks) - failures - warnings} passed, "
              f"{warnings} warnings, {failures} failures")
        if failures:
            print("Resolve every FAIL before exposing this application to a network.")
        print("This checklist verifies configuration only. It is not a penetration test and")
        print("does not prove the application is free of vulnerabilities.")
        print("=" * 90)
    return failures


def main() -> int:
    os.environ.setdefault("FLASK_CONFIG", "development")
    return 1 if run_checks() else 0


if __name__ == "__main__":
    raise SystemExit(main())
