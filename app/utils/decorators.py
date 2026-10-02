"""Authorisation decorators built on Flask-Login + the Role matrix."""

from __future__ import annotations

from functools import wraps

from flask import abort, flash, jsonify, redirect, request, url_for
from flask_login import current_user

from app.models.audit_log import AuditAction
from app.utils.audit import log_audit


def _wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] >= accept["text/html"] and accept["application/json"] > 0


def _deny(reason: str, target: str):
    log_audit(
        AuditAction.ACCESS_DENIED,
        status="BLOCKED",
        description=reason,
        target_type="route",
        target_id=target,
    )
    if _wants_json():
        response = jsonify({"success": False, "error": {"code": "forbidden", "message": reason}})
        response.status_code = 403
        return response
    abort(403)


def role_required(*roles: str):
    """Allow the view only for the listed roles."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if _wants_json():
                    return (
                        jsonify({"success": False, "error": {"code": "unauthorized",
                                                             "message": "Authentication required."}}),
                        401,
                    )
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("auth.login", next=request.full_path))
            if not current_user.has_role(*roles):
                return _deny(
                    f"Role {current_user.role} attempted to access {request.path}",
                    request.endpoint or request.path,
                )
            return view(*args, **kwargs)

        return wrapper

    return decorator


def capability_required(capability: str):
    """Allow the view only for roles holding ``capability``."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if _wants_json():
                    return (
                        jsonify({"success": False, "error": {"code": "unauthorized",
                                                             "message": "Authentication required."}}),
                        401,
                    )
                flash("Please sign in to continue.", "warning")
                return redirect(url_for("auth.login", next=request.full_path))
            if not current_user.can(capability):
                return _deny(
                    f"Role {current_user.role} lacks capability {capability}",
                    request.endpoint or request.path,
                )
            return view(*args, **kwargs)

        return wrapper

    return decorator


def admin_required(view):
    """Shorthand for :func:`role_required` with the ADMIN role."""
    from app.models.user import Role

    return role_required(Role.ADMIN)(view)
