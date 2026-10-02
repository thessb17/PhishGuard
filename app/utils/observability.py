"""Request correlation IDs and structured security logging.

Two problems this solves:

1. **Correlation.** When a user reports "it failed", a bare log line is hard
   to tie to their request. Every request now gets an ID, which is attached to
   every log line it produces, returned in the ``X-Request-ID`` response
   header, and included in API error bodies — so a screenshot of an error is
   enough to find the exact log entries.

2. **Machine-readable security events.** Human-prose log lines are fine to
   read and useless to search. Security-relevant events are emitted as JSON
   with a stable field set, so they can be grepped, shipped, or loaded into a
   SIEM without parsing English.

Redaction is enforced here rather than trusted to callers: the emitter drops
any field whose name looks sensitive, so a careless ``extra={"password": ...}``
cannot leak through this path.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone

from flask import g, has_request_context, request

#: Header clients may send to supply their own correlation ID.
REQUEST_ID_HEADER = "X-Request-ID"

#: Field names never written to a log record, whatever the caller passes.
_FORBIDDEN_FIELDS = {
    "password", "passwd", "pwd", "new_password", "current_password",
    "confirm_password", "token", "api_key", "apikey", "secret", "authorization",
    "session", "cookie", "card", "cvv", "iban", "otp", "body", "raw_email",
}

_MAX_VALUE_LEN = 256


def new_request_id() -> str:
    """Short, URL-safe, collision-resistant enough for log correlation."""
    return uuid.uuid4().hex[:16]


def current_request_id() -> str:
    """The active request's ID, or ``-`` outside a request context."""
    if has_request_context():
        return getattr(g, "request_id", "-") or "-"
    return "-"


def _sanitise(payload: dict | None) -> dict:
    """Drop sensitive keys, coerce to scalars, bound the size."""
    if not payload:
        return {}
    clean: dict = {}
    for key, value in payload.items():
        k = str(key)
        if k.lower() in _FORBIDDEN_FIELDS:
            clean[k] = "[REDACTED]"
            continue
        if isinstance(value, (int, float, bool)) or value is None:
            clean[k] = value
        else:
            clean[k] = str(value)[:_MAX_VALUE_LEN]
    return clean


class RequestIdFilter(logging.Filter):
    """Make ``%(request_id)s`` usable in any formatter."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        record.request_id = current_request_id()
        return True


class JsonSecurityFormatter(logging.Formatter):
    """One JSON object per line, for the security event stream."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "request_id": getattr(record, "request_id", "-"),
            "message": record.getMessage(),
        }
        for key in ("actor", "action", "resource", "outcome", "ip", "method",
                    "path", "status", "duration_ms", "event"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload["extra"] = extra
        return json.dumps(payload, default=str, separators=(",", ":"))


def log_security_event(
    action: str,
    *,
    outcome: str = "SUCCESS",
    actor: str | None = None,
    resource: str | None = None,
    level: int = logging.INFO,
    **extra,
) -> None:
    """Emit one structured security event.

    Complements (does not replace) the ``audit_logs`` table: the table is the
    durable, queryable record shown in the UI; this is the log stream an
    operator can tail or forward. Both deliberately carry the same request ID.
    """
    logger = logging.getLogger("phishguard.security")
    if actor is None and has_request_context():
        try:
            from flask_login import current_user

            if getattr(current_user, "is_authenticated", False):
                actor = current_user.username
        except Exception:  # noqa: BLE001 - logging must never break a request
            actor = None

    record_extra = {
        "event": "security",
        "action": action,
        "outcome": outcome,
        "actor": actor or "anonymous",
        "resource": resource or (request.path if has_request_context() else None),
        "ip": (request.remote_addr if has_request_context() else None),
        "extra_fields": _sanitise(extra),
    }
    logger.log(level, "security.%s", action, extra=record_extra)


def init_observability(app) -> None:
    """Install request-ID handling and the structured security logger."""

    security_logger = logging.getLogger("phishguard.security")
    security_logger.setLevel(app.config.get("LOG_LEVEL", "INFO"))
    security_logger.propagate = False

    if not security_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonSecurityFormatter())
        handler.addFilter(RequestIdFilter())
        security_logger.addHandler(handler)

        # In production also persist the JSON stream next to the app log, so
        # the events survive a container restart.
        log_file = app.config.get("SECURITY_LOG_FILE")
        if log_file:
            try:
                from pathlib import Path

                Path(log_file).parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file, encoding="utf-8")
                file_handler.setFormatter(JsonSecurityFormatter())
                file_handler.addFilter(RequestIdFilter())
                security_logger.addHandler(file_handler)
            except OSError:  # pragma: no cover - unwritable path must not abort boot
                app.logger.warning("security log file not writable: %s", log_file)

    # Make request_id available to the ordinary application logger too.
    app.logger.addFilter(RequestIdFilter())

    @app.before_request
    def _assign_request_id():  # pragma: no cover - exercised via the test client
        supplied = request.headers.get(REQUEST_ID_HEADER, "").strip()
        # Accept a client-supplied ID only if it is short and alphanumeric;
        # otherwise it is attacker-controlled data heading for the log file.
        if supplied and len(supplied) <= 64 and supplied.replace("-", "").isalnum():
            g.request_id = supplied
        else:
            g.request_id = new_request_id()
        g.request_started_at = time.perf_counter()

    @app.after_request
    def _attach_request_id(response):  # pragma: no cover - exercised via the client
        rid = current_request_id()
        if rid and rid != "-":
            response.headers[REQUEST_ID_HEADER] = rid
        started = getattr(g, "request_started_at", None)
        if started is not None and response.status_code >= 400:
            # Only log the failures; logging every 200 would drown the signal.
            logging.getLogger("phishguard.security").info(
                "http.%s", response.status_code,
                extra={
                    "event": "http",
                    "action": f"http_{response.status_code}",
                    "outcome": "FAILURE" if response.status_code >= 500 else "REJECTED",
                    "actor": None,
                    "resource": request.path,
                    "ip": request.remote_addr,
                    "method": request.method,
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    "extra_fields": {},
                },
            )
        return response
