"""Administration: audit-log viewer and user management."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from app.extensions import db
from app.forms import SimpleActionForm
from app.models.audit_log import AuditAction, AuditLog
from app.models.user import Role, User
from app.utils.audit import log_audit
from app.utils.decorators import capability_required

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/audit-logs")
@login_required
@capability_required("audit.view")
def audit_logs():
    page = request.args.get("page", 1, type=int)
    action = (request.args.get("action") or "").upper()
    category = (request.args.get("category") or "").lower()
    status = (request.args.get("status") or "").upper()
    search = (request.args.get("q") or "").strip()

    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action == action)
    if category:
        query = query.filter(AuditLog.category == category)
    if status:
        query = query.filter(AuditLog.status == status)
    if search:
        pattern = f"%{search[:64]}%"
        query = query.filter(or_(AuditLog.actor_username.ilike(pattern),
                                 AuditLog.description.ilike(pattern)))

    pagination = query.order_by(AuditLog.created_at.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    actions = sorted({row[0] for row in db.session.query(AuditLog.action).distinct().all()})
    categories = sorted({row[0] for row in db.session.query(AuditLog.category).distinct().all()})
    return render_template("admin/audit_logs.html", pagination=pagination, actions=actions,
                           categories=categories, selected_action=action,
                           selected_category=category, selected_status=status, search=search)


@admin_bp.route("/users")
@login_required
@capability_required("user.manage")
def users():
    page = request.args.get("page", 1, type=int)
    role_filter = (request.args.get("role") or "").upper()
    query = User.query
    if role_filter in Role.ALL:
        query = query.filter(User.role == role_filter)
    pagination = query.order_by(User.created_at.asc()).paginate(page=page, per_page=20,
                                                                error_out=False)
    form = SimpleActionForm()
    return render_template("admin/users.html", pagination=pagination, form=form,
                           roles=Role.ALL, role_labels=Role.LABELS, role_filter=role_filter)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@login_required
@capability_required("user.manage")
def change_role(user_id: int):
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    new_role = (request.form.get("role") or "").upper()
    if new_role not in Role.ALL:
        flash("Unknown role.", "danger")
        return redirect(url_for("admin.users"))
    if user.id == current_user.id and new_role != Role.ADMIN:
        flash("You cannot remove your own administrator role.", "warning")
        return redirect(url_for("admin.users"))

    previous = user.role
    user.role = new_role
    db.session.commit()
    log_audit(AuditAction.ROLE_CHANGED,
              description=f"Role for {user.username} changed {previous} -> {new_role}",
              target_type="user", target_id=user.id,
              extra={"from": previous, "to": new_role})
    flash(f"Role for {user.username} updated to {Role.LABELS[new_role]}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/status", methods=["POST"])
@login_required
@capability_required("user.manage")
def change_status(user_id: int):
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot disable your own account.", "warning")
        return redirect(url_for("admin.users"))

    user.is_active_account = not user.is_active_account
    user.locked_until = None
    user.failed_login_count = 0
    db.session.commit()
    state = "enabled" if user.is_active_account else "disabled"
    log_audit(AuditAction.USER_STATUS_CHANGED,
              description=f"Account {user.username} {state}",
              target_type="user", target_id=user.id, extra={"state": state})
    flash(f"Account {user.username} {state}.", "success")
    return redirect(url_for("admin.users"))
