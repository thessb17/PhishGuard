"""Authentication, registration, session management and profile."""

from __future__ import annotations

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, request, session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func, or_

from app.extensions import db, limiter
from app.forms import ChangePasswordForm, LoginForm, RegistrationForm, SimpleActionForm
from app.models.audit_log import AuditAction
from app.models.quiz import QuizAttempt
from app.models.simulation import SimulationEvent
from app.models.user import Role, User
from app.utils.audit import log_audit
from app.utils.security import is_safe_redirect_url

auth_bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid credentials. Please check your details and try again."


def _login_limit():
    return current_app.config.get("RATELIMIT_LOGIN", "10 per minute;60 per hour")


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(_login_limit, methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = (form.username.data or "").strip().lower()
        user = User.query.filter(
            or_(func.lower(User.username) == identifier, func.lower(User.email) == identifier)
        ).first()

        # Generic errors only: never reveal whether the account exists.
        if user and user.is_locked:
            log_audit(AuditAction.LOGIN_BLOCKED, status="BLOCKED",
                      description="Login attempt on a locked account", actor=user,
                      target_type="user", target_id=user.id)
            flash("This account is temporarily locked after repeated failed attempts. "
                  "Try again later.", "danger")
            return render_template("auth/login.html", form=form), 423

        if user and user.check_password(form.password.data or ""):
            if not user.is_active:
                log_audit(AuditAction.LOGIN_BLOCKED, status="BLOCKED",
                          description="Login attempt on a disabled account", actor=user,
                          target_type="user", target_id=user.id)
                flash("This account has been disabled. Contact an administrator.", "danger")
                return render_template("auth/login.html", form=form), 403

            user.register_successful_login()
            db.session.commit()
            login_user(user, remember=bool(form.remember.data))
            log_audit(AuditAction.LOGIN_SUCCESS, description=f"User {user.username} signed in",
                      actor=user, target_type="user", target_id=user.id)
            flash(f"Welcome back, {user.full_name or user.username}.", "success")

            next_page = request.args.get("next") or request.form.get("next")
            if next_page and is_safe_redirect_url(next_page):
                return redirect(next_page)
            return redirect(url_for("dashboard.home"))

        if user:
            locked = user.register_failed_login()
            db.session.commit()
            log_audit(AuditAction.LOGIN_FAILURE, status="FAILURE",
                      description="Failed password verification", actor=user,
                      target_type="user", target_id=user.id,
                      extra={"account_locked": locked})
        else:
            log_audit(AuditAction.LOGIN_FAILURE, status="FAILURE",
                      description="Failed login for unknown identifier",
                      extra={"identifier_supplied": bool(identifier)})
        flash(GENERIC_LOGIN_ERROR, "danger")
        return render_template("auth/login.html", form=form), 401

    if form.errors:
        flash(GENERIC_LOGIN_ERROR, "danger")
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    username = current_user.username
    log_audit(AuditAction.LOGOUT, description=f"User {username} signed out",
              target_type="user", target_id=current_user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def register():
    """Self-service registration - creates DEMO_USER accounts only.

    Elevated roles can never be obtained through this endpoint; an
    administrator must promote the account explicitly.
    """
    if not current_app.config.get("ALLOW_SELF_REGISTRATION", True):
        abort(404)
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = (form.username.data or "").strip().lower()
        email = (form.email.data or "").strip().lower()
        existing = User.query.filter(
            or_(func.lower(User.username) == username, func.lower(User.email) == email)
        ).first()
        if existing:
            flash("That username or email is already registered.", "danger")
            return render_template("auth/register.html", form=form), 409

        user = User(
            username=username,
            email=email,
            full_name=(form.full_name.data or "").strip(),
            department=(form.department.data or "General").strip(),
            organization="Andhra University",
            role=Role.DEMO_USER,  # hard-coded: registration cannot grant privilege
        )
        user.set_password(form.password.data)
        user.ensure_api_key()
        db.session.add(user)
        db.session.commit()
        log_audit(AuditAction.REGISTER, description=f"Demo account created: {user.username}",
                  actor=user, target_type="user", target_id=user.id)
        flash("Demo account created. You can sign in now.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/profile")
@login_required
def profile():
    password_form = ChangePasswordForm()
    action_form = SimpleActionForm()
    events = (
        SimulationEvent.query.filter_by(user_id=current_user.id)
        .order_by(SimulationEvent.occurred_at.desc()).limit(15).all()
    )
    attempts = (
        QuizAttempt.query.filter_by(user_id=current_user.id)
        .order_by(QuizAttempt.completed_at.desc()).limit(10).all()
    )
    best_score = max((a.score for a in attempts), default=None)
    # One-shot reveal: a freshly rotated key is displayed on this render only.
    # Popping it means a refresh, a back-button press or a second visit will
    # not show it again - matching the fact that we cannot recover it either.
    new_api_key = session.pop("new_api_key", None)
    return render_template(
        "auth/profile.html",
        password_form=password_form,
        action_form=action_form,
        events=events,
        attempts=attempts,
        best_score=best_score,
        new_api_key=new_api_key,
        capabilities=Role.capabilities_for(current_user.role),
    )


@auth_bp.route("/profile/password", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data or ""):
            log_audit(AuditAction.PASSWORD_CHANGED, status="FAILURE",
                      description="Password change rejected: current password incorrect",
                      target_type="user", target_id=current_user.id)
            flash("Your current password is incorrect.", "danger")
            return redirect(url_for("auth.profile"))
        current_user.set_password(form.new_password.data)
        db.session.commit()
        log_audit(AuditAction.PASSWORD_CHANGED, description="Password updated",
                  target_type="user", target_id=current_user.id)
        flash("Password updated successfully.", "success")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field.replace('_', ' ').title()}: {error}", "danger")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/profile/api-key", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def rotate_api_key():
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    raw_key = current_user.rotate_api_key()
    db.session.commit()
    # The audit record deliberately carries no key material - only the fact of
    # the rotation and the non-secret prefix that identifies the new key.
    log_audit(AuditAction.API_KEY_ROTATED, description="API key rotated",
              target_type="user", target_id=current_user.id,
              extra={"key_prefix": current_user.api_key_prefix})
    # Only the digest is stored, so this is the single moment the plaintext
    # can be shown. Stash it for exactly one render of the profile page.
    session["new_api_key"] = raw_key
    flash("A new API key has been generated. Copy it now - it cannot be shown again.",
          "success")
    return redirect(url_for("auth.profile"))


@auth_bp.route("/auth/session-reset")
def session_reset():
    """Development-only recovery from a stale or unusable browser session.

    A browser can hold a session cookie the server can no longer verify (for
    example after SECRET_KEY changed, or after switching between app
    instances). Flask discards the unverifiable session, so every form POST
    then fails CSRF validation with no obvious way out from inside the
    browser. This clears the cookie and sends the user back to a clean login.

    It is registered ONLY outside production. It performs no authentication
    and reveals nothing, but an endpoint that drops sessions has no business
    existing on a production deployment.
    """
    if current_app.config.get("ENV_NAME") == "production":
        abort(404)
    logout_user()
    session.clear()
    flash("Local session cleared. Please sign in again.", "info")
    response = redirect(url_for("auth.login"))
    response.delete_cookie(current_app.config.get("SESSION_COOKIE_NAME", "session"))
    response.headers["Cache-Control"] = "no-store"
    return response


@auth_bp.route("/__debug__/session")
def debug_session():
    """Development-only session diagnostics.

    Answers the one question that matters when CSRF fails: *is the session
    cookie actually coming back?* Returns presence booleans and cookie
    policy only - never the CSRF token, session values, or any secret.

    Registered outside production only, and returns 404 there.
    """
    if current_app.config.get("ENV_NAME") == "production":
        abort(404)

    from flask import jsonify

    from app.utils.observability import current_request_id

    cookie_name = current_app.config.get("SESSION_COOKIE_NAME", "session")
    payload = {
        "session_cookie_present": cookie_name in request.cookies,
        # Key NAMES only, and the CSRF key is excluded: "csrf_session_present"
        # below already reports it, so echoing the name adds nothing.
        "session_keys": sorted(k for k in session.keys()
                               if k != "csrf_token" and not k.startswith("_csrf")),
        "csrf_session_present": "csrf_token" in session,
        "authenticated": bool(getattr(current_user, "is_authenticated", False)),
        "user": getattr(current_user, "username", None) if getattr(
            current_user, "is_authenticated", False) else None,
        "scheme": request.scheme,
        "host": request.host,
        "secure_cookie": bool(current_app.config.get("SESSION_COOKIE_SECURE")),
        "samesite": current_app.config.get("SESSION_COOKIE_SAMESITE"),
        "csrf_time_limit": current_app.config.get("WTF_CSRF_TIME_LIMIT"),
        "config": current_app.config.get("ENV_NAME"),
        "request_id": current_request_id(),
    }
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response
