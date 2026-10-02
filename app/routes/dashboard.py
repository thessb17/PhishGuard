"""SOC-style dashboard."""

from __future__ import annotations

from flask import Blueprint, jsonify, redirect, render_template, url_for
from flask_login import current_user, login_required

from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.email_analysis import EmailAnalysis
from app.models.simulation import SimulationEvent
from app.models.url_analysis import URLAnalysis
from app.models.user import Role, User
from app.services.campaign_service import dashboard_stats, detection_accuracy_series
from app.utils.decorators import capability_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
    return redirect(url_for("dashboard.home"))


@dashboard_bp.route("/home")
@login_required
def home():
    """Role-aware landing page."""
    if current_user.can("dashboard.view"):
        return redirect(url_for("dashboard.dashboard"))
    return redirect(url_for("simulator.inbox"))


@dashboard_bp.route("/dashboard")
@login_required
@capability_required("dashboard.view")
def dashboard():
    stats = dashboard_stats()
    accuracy = detection_accuracy_series()
    recent_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(5).all()
    recent_events = (
        SimulationEvent.query.order_by(SimulationEvent.occurred_at.desc()).limit(8).all()
    )
    recent_urls = URLAnalysis.query.order_by(URLAnalysis.created_at.desc()).limit(5).all()
    recent_emails = EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).limit(5).all()
    recent_audit = (
        AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
        if current_user.can("audit.view") else []
    )
    training_users = (
        User.query.filter(User.id.in_(stats["needs_training_ids"])).all()
        if stats["needs_training_ids"] else []
    )
    return render_template(
        "dashboard/index.html",
        stats=stats,
        accuracy=accuracy,
        recent_campaigns=recent_campaigns,
        recent_events=recent_events,
        recent_urls=recent_urls,
        recent_emails=recent_emails,
        recent_audit=recent_audit,
        training_users=training_users,
        Role=Role,
    )


@dashboard_bp.route("/dashboard/data")
@login_required
@capability_required("dashboard.view")
def dashboard_data():
    """JSON feed used by the Chart.js widgets (and handy for API demos)."""
    return jsonify({
        "success": True,
        "data": {**dashboard_stats(), "accuracy": detection_accuracy_series()},
    })


@dashboard_bp.route("/health")
def health():
    """Unauthenticated liveness/readiness probe.

    Reports component status only - never a connection string, file path,
    secret, token, or version of any dependency. Returns 503 when a
    component is unavailable so an orchestrator can act on it.
    """
    from flask import current_app, jsonify

    from app.extensions import db

    database = "ok"
    try:
        db.session.execute(db.text("SELECT 1"))
    except Exception:  # noqa: BLE001 - detail is deliberately not surfaced
        database = "error"

    ml = "ok"
    try:
        from app.ml.predict import model_available

        if not (current_app.config.get("ML_ENABLED") and model_available()):
            ml = "unavailable"
    except Exception:  # noqa: BLE001
        ml = "error"

    degraded = database != "ok" or ml not in ("ok", "unavailable")
    payload = {
        "status": "degraded" if degraded else "ok",
        "service": current_app.config.get("APP_NAME", "PhishGuard"),
        "version": current_app.config.get("VERSION", "unknown"),
        "database": database,
        "ml": ml,
    }
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response, (503 if degraded else 200)
