"""Helper for writing audit-trail entries."""

from __future__ import annotations

from flask import current_app, has_request_context, request
from flask_login import current_user

from app.extensions import db
from app.models.audit_log import AuditAction, AuditLog

#: Keys that must never be written into the audit trail.
_FORBIDDEN_KEYS = {
    "password", "passwd", "pwd", "new_password", "current_password", "confirm_password",
    "token", "api_key", "apikey", "secret", "authorization", "session", "cookie",
    "card", "cvv", "iban", "otp", "body",
}


def _sanitise_extra(extra: dict | None) -> dict:
    if not extra:
        return {}
    clean: dict = {}
    for key, value in extra.items():
        if str(key).lower() in _FORBIDDEN_KEYS:
            clean[str(key)] = "[REDACTED]"
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            clean[str(key)] = value if not isinstance(value, str) else value[:256]
        elif isinstance(value, (list, tuple)):
            clean[str(key)] = [str(v)[:128] for v in list(value)[:20]]
        elif isinstance(value, dict):
            clean[str(key)] = {str(k)[:64]: str(v)[:128] for k, v in list(value.items())[:20]}
        else:
            clean[str(key)] = str(value)[:256]
    return clean


def log_audit(action: str, *, status: str = "SUCCESS", description: str = "",
              target_type: str | None = None, target_id=None, actor=None,
              extra: dict | None = None, commit: bool = True) -> AuditLog:
    """Record a security-relevant event.

    Never pass secrets in ``extra`` - values under known-sensitive keys are
    masked, and free text should already be redacted by the caller.
    """
    actor_obj = actor
    if actor_obj is None:
        try:
            actor_obj = current_user if getattr(current_user, "is_authenticated", False) else None
        except Exception:  # pragma: no cover - outside request context
            actor_obj = None

    ip_address = None
    user_agent = None
    if has_request_context():
        if current_app.config.get("AUDIT_LOG_IP", True):
            ip_address = (request.headers.get("X-Forwarded-For", request.remote_addr) or "")[:64]
        user_agent = (request.headers.get("User-Agent") or "")[:255]

    entry = AuditLog(
        actor_id=getattr(actor_obj, "id", None),
        actor_username=getattr(actor_obj, "username", None) or "anonymous",
        actor_role=getattr(actor_obj, "role", None) or "anonymous",
        action=action,
        category=AuditAction.CATEGORIES.get(action, "general"),
        status=status,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        description=(description or "")[:512],
        ip_address=ip_address,
        user_agent=user_agent,
        extra=_sanitise_extra(extra),
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry
