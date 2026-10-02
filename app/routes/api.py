"""REST-style JSON API.

Authentication
--------------
Two mechanisms are accepted:

* **Session cookie** (the logged-in browser session).  Because the blueprint
  is exempt from the global form-CSRF handling, unsafe methods additionally
  require a valid ``X-CSRFToken`` header - otherwise a malicious site could
  drive the API with the victim's cookie.
* **API key** in ``X-API-Key`` (or ``Authorization: Bearer <key>``).  Keys are
  per-user, carry that user's role, and are not cookies - so CSRF does not
  apply to them.

Every response uses the same envelope::

    {"success": true,  "data": {...}}
    {"success": false, "error": {"code": "...", "message": "..."}}
"""

from __future__ import annotations

from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request
from flask_login import current_user
from flask_wtf.csrf import CSRFError, validate_csrf

from app.extensions import db, limiter
from app.models.audit_log import AuditAction
from app.models.campaign import Campaign, CampaignStatus, Difficulty
from app.models.quiz import AwarenessQuiz, QuizAttempt, QuizQuestion
from app.models.report import Report
from app.models.user import Role, User
from app.routes.awareness import grade_quiz
from app.routes.email_detector import analyse_email_payload
from app.routes.url_detector import analyse_url_payload
from app.services.awareness_content import ensure_default_quiz
from app.services.campaign_service import (
    CampaignError, campaign_stats, create_campaign, dashboard_stats,
)
from app.services.ml_detector import ml_detector
from app.services.simulation_templates import TEMPLATES
from app.utils.audit import log_audit
from app.utils.observability import current_request_id
from app.utils.validators import (
    ValidationError, validate_choice, validate_int, validate_text, validate_url,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

def ok(data, status: int = 200):
    """Success envelope.

    ``error`` is present and null on success, and ``data`` is present and null
    on failure, so a client can destructure the same shape either way instead
    of branching on which keys exist.
    """
    return jsonify({
        "success": True,
        "data": data,
        "error": None,
        "request_id": current_request_id(),
    }), status


def fail(code: str, message: str, status: int = 400, **extra):
    payload = {"code": code, "message": message}
    payload.update(extra)
    return jsonify({
        "success": False,
        "data": None,
        "error": payload,
        "request_id": current_request_id(),
    }), status


# ---------------------------------------------------------------------------
# Authentication / authorisation
# ---------------------------------------------------------------------------

def _user_from_api_key():
    key = request.headers.get("X-API-Key")
    if not key:
        header = request.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            key = header[7:].strip()
    if not key or len(key) < 16:
        return None
    # Keys are stored as a SHA-256 digest, so we hash the presented value and
    # look *that* up.  This stays a single indexed query - no table scan, no
    # per-row comparison - so hashing costs nothing at request time.
    user = User.query.filter_by(api_key_hash=User.hash_api_key(key)).first()
    if user is None or not user.verify_api_key(key):
        return None
    return user


def api_auth(capability: str | None = None):
    """Authenticate the caller and enforce a capability."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = _user_from_api_key()
            via = "api_key"
            if user is None and current_user.is_authenticated:
                user, via = current_user, "session"
            if user is None or not user.is_active:
                return fail("unauthorized",
                            "Provide a valid session cookie or X-API-Key header.", 401)

            # Cookie-authenticated unsafe requests still need a CSRF token.
            if (via == "session" and request.method not in ("GET", "HEAD", "OPTIONS")
                    and current_app.config.get("WTF_CSRF_ENABLED", True)):
                token = request.headers.get("X-CSRFToken") or request.headers.get("X-CSRF-Token")
                try:
                    validate_csrf(token)
                except (CSRFError, Exception):  # noqa: BLE001 - any failure is a rejection
                    return fail("csrf_required",
                                "Session-authenticated writes require an X-CSRFToken header. "
                                "Use an API key for non-browser clients.", 403)

            if capability and not user.can(capability):
                log_audit(AuditAction.ACCESS_DENIED, status="BLOCKED", actor=user,
                          description=f"API capability {capability} denied for role {user.role}",
                          target_type="api", target_id=request.path)
                return fail("forbidden", f"Role {user.role} lacks capability '{capability}'.", 403)

            g.api_user = user
            g.api_auth_method = via
            return view(*args, **kwargs)

        return wrapper

    return decorator


def _json_body() -> dict:
    data = request.get_json(silent=True)
    if data is None and request.form:
        data = request.form.to_dict()
    return data if isinstance(data, dict) else {}


@api_bp.errorhandler(429)
def _api_rate_limited(error):  # pragma: no cover - exercised through the limiter
    return fail("rate_limited", "Rate limit exceeded. Slow down and retry.", 429)


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@api_bp.route("/health")
@limiter.exempt
def health():
    return ok({
        "status": "ok",
        "app": current_app.config.get("APP_NAME"),
        "version": current_app.config.get("VERSION"),
        "environment": current_app.config.get("ENV_NAME"),
        "ml_model": ml_detector.metadata(),
    })


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@api_bp.route("/analyze/url", methods=["POST"])
@api_auth("analysis.run")
@limiter.limit("120 per minute")
def analyze_url():
    body = _json_body()
    try:
        url = validate_url(body.get("url"))
    except ValidationError as exc:
        return fail("validation_error", exc.message, 400, field=exc.field)

    persist = bool(body.get("persist", True))
    rule_result, ml_result, risk, record = analyse_url_payload(
        url, analyst=g.api_user, source="api", persist=persist
    )
    if record:
        log_audit(AuditAction.ANALYSIS_PERFORMED, actor=g.api_user,
                  description=f"API URL analysis #{record.id}: {risk.classification}",
                  target_type="url_analysis", target_id=record.id,
                  extra={"classification": risk.classification, "via": g.api_auth_method})
    return ok({
        "analysis_id": record.id if record else None,
        "url": rule_result["url"],
        "hostname": rule_result["hostname"],
        "classification": risk.classification,
        "risk_score": risk.final_score,
        "heuristic_score": risk.heuristic_score,
        "ml": {
            "available": bool(ml_result.get("available")),
            "model": ml_result.get("model"),
            "classification": ml_result.get("classification"),
            "risk_score": ml_result.get("risk_score"),
            "confidence": ml_result.get("confidence"),
            "explanation": ml_result.get("explanation", []),
            "reason": ml_result.get("reason"),
        },
        "weights": risk.weights,
        "indicators": rule_result["indicators"],
        "features": rule_result["features"]["numeric"],
        "explanation": risk.explanation,
        "recommendation": risk.to_dict()["recommendation"],
        "disclaimer": rule_result["disclaimer"],
    })


@api_bp.route("/analyze/email", methods=["POST"])
@api_auth("analysis.run")
@limiter.limit("60 per minute")
def analyze_email():
    body = _json_body()
    try:
        message_body = validate_text(body.get("body"), "Body", min_length=10, max_length=50000)
        sender = validate_text(body.get("sender"), "Sender", required=False, max_length=320)
        subject = validate_text(body.get("subject"), "Subject", required=False, max_length=512)
        headers = validate_text(body.get("headers"), "Headers", required=False, max_length=20000)
    except ValidationError as exc:
        return fail("validation_error", exc.message, 400, field=exc.field)

    raw_urls = body.get("urls") or []
    if isinstance(raw_urls, str):
        raw_urls = [line.strip() for line in raw_urls.splitlines() if line.strip()]
    urls = [str(u)[:2048] for u in list(raw_urls)[:20]]

    rule_result, ml_result, risk, record = analyse_email_payload(
        sender=sender, subject=subject, body=message_body, urls=urls,
        headers=headers, analyst=g.api_user, persist=bool(body.get("persist", True)),
    )
    if record:
        log_audit(AuditAction.ANALYSIS_PERFORMED, actor=g.api_user,
                  description=f"API email analysis #{record.id}: {risk.classification}",
                  target_type="email_analysis", target_id=record.id,
                  extra={"classification": risk.classification, "via": g.api_auth_method})
    return ok({
        "analysis_id": record.id if record else None,
        "sender": rule_result["sender"],
        "subject": rule_result["subject"],
        "classification": risk.classification,
        "risk_score": risk.final_score,
        "heuristic_score": risk.heuristic_score,
        "ml": {
            "available": bool(ml_result.get("available")),
            "model": ml_result.get("model"),
            "risk_score": ml_result.get("risk_score"),
            "confidence": ml_result.get("confidence"),
            "scored_url": (rule_result.get("worst_url") or {}).get("url"),
        },
        "weights": risk.weights,
        "indicators": rule_result["indicators"],
        "urls": rule_result["urls"],
        "header_findings": rule_result["header_findings"],
        "explanation": risk.explanation,
        "recommendation": risk.to_dict()["recommendation"],
        "disclaimer": rule_result["disclaimer"],
    })


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------

@api_bp.route("/campaigns", methods=["GET"])
@api_auth("campaign.view")
def list_campaigns():
    limit = min(request.args.get("limit", 25, type=int), 100)
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(limit).all()
    payload = []
    for campaign in campaigns:
        stats = campaign_stats(campaign)
        payload.append({
            **campaign.to_dict(),
            "statistics": {
                "participants": stats["participants"],
                "interaction_rate": stats["interaction_rate"],
                "report_rate": stats["report_rate"],
                "awareness_score": stats["awareness_score"],
                "risk_level": stats["risk_level"],
            },
        })
    return ok({"count": len(payload), "campaigns": payload})


@api_bp.route("/campaigns", methods=["POST"])
@api_auth("campaign.create")
@limiter.limit("30 per hour")
def create_campaign_api():
    body = _json_body()
    try:
        name = validate_text(body.get("name"), "Name", min_length=3, max_length=160)
        description = validate_text(body.get("description"), "Description",
                                    required=False, max_length=2000)
        template_key = validate_text(body.get("template_key"), "Template key", max_length=64)
        if template_key not in TEMPLATES:
            return fail("validation_error",
                        f"Unknown template '{template_key}'. Valid keys: "
                        f"{', '.join(sorted(TEMPLATES))}.", 400, field="template_key")
        difficulty = validate_choice(body.get("difficulty", "MEDIUM"), Difficulty.ALL, "Difficulty")
        status = validate_choice(body.get("status", CampaignStatus.ACTIVE),
                                 (CampaignStatus.DRAFT, CampaignStatus.ACTIVE), "Status")
        raw_targets = body.get("target_ids") or []
        if not isinstance(raw_targets, (list, tuple)) or not raw_targets:
            return fail("validation_error", "target_ids must be a non-empty list of user ids.",
                        400, field="target_ids")
        target_ids = [validate_int(t, "target id", minimum=1) for t in raw_targets[:200]]
    except ValidationError as exc:
        return fail("validation_error", exc.message, 400, field=exc.field)

    try:
        campaign = create_campaign(
            name=name, description=description, template_key=template_key,
            difficulty=difficulty, start_date=None, end_date=None,
            target_ids=target_ids, creator=g.api_user, status=status,
        )
    except CampaignError as exc:
        return fail("campaign_error", str(exc), 400)

    log_audit(AuditAction.CAMPAIGN_CREATED, actor=g.api_user,
              description=f"Campaign '{campaign.name}' created via API",
              target_type="campaign", target_id=campaign.id,
              extra={"template": template_key, "via": g.api_auth_method})
    return ok({"campaign": campaign.to_dict()}, 201)


@api_bp.route("/campaigns/<int:campaign_id>", methods=["GET"])
@api_auth("campaign.view")
def campaign_detail(campaign_id: int):
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign:
        return fail("not_found", "Campaign not found.", 404)
    stats = campaign_stats(campaign)
    stats["participant_rows"] = [
        {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()}
        for row in stats["participant_rows"]
    ]
    return ok(stats)


# ---------------------------------------------------------------------------
# Reports / dashboard / quiz
# ---------------------------------------------------------------------------

@api_bp.route("/reports/<int:report_id>", methods=["GET"])
@api_auth("report.view")
def get_report(report_id: int):
    report = db.session.get(Report, report_id)
    if not report:
        return fail("not_found", "Report not found.", 404)
    return ok(report.to_dict())


@api_bp.route("/dashboard/stats", methods=["GET"])
@api_auth("dashboard.view")
def dashboard_api():
    return ok(dashboard_stats())


@api_bp.route("/ml/metadata", methods=["GET"])
@api_auth("analysis.view")
def ml_metadata():
    return ok(ml_detector.metadata())


@api_bp.route("/quiz", methods=["GET"])
@api_auth("awareness.view")
def get_quiz():
    quiz = ensure_default_quiz(db.session, AwarenessQuiz, QuizQuestion)
    return ok(quiz.to_dict(include_answers=False))


@api_bp.route("/quiz/submit", methods=["POST"])
@api_auth("awareness.view")
@limiter.limit("20 per hour")
def submit_quiz_api():
    quiz = ensure_default_quiz(db.session, AwarenessQuiz, QuizQuestion)
    body = _json_body()
    raw_answers = body.get("answers")
    if not isinstance(raw_answers, dict) or not raw_answers:
        return fail("validation_error",
                    'answers must be an object mapping question id -> selected option index, '
                    'e.g. {"answers": {"1": 2, "2": 0}}.', 400, field="answers")

    valid_ids = {question.id: question for question in quiz.questions}
    submitted: dict[int, int] = {}
    for key, value in list(raw_answers.items())[:100]:
        try:
            question_id, selected = int(key), int(value)
        except (TypeError, ValueError):
            return fail("validation_error", "Question ids and answers must be integers.", 400)
        question = valid_ids.get(question_id)
        if not question:
            return fail("validation_error", f"Unknown question id {question_id}.", 400)
        if not 0 <= selected < len(question.options or []):
            return fail("validation_error",
                        f"Option index {selected} is out of range for question {question_id}.", 400)
        submitted[question_id] = selected

    attempt = grade_quiz(quiz, submitted, g.api_user)
    log_audit(AuditAction.QUIZ_SUBMITTED, actor=g.api_user,
              description=f"Quiz submitted via API: {attempt.score}%",
              target_type="quiz_attempt", target_id=attempt.id,
              extra={"score": attempt.score, "via": g.api_auth_method})
    return ok({
        "attempt": attempt.to_dict(),
        "results": [
            {
                "question_id": row["question_id"],
                "correct": row["correct"],
                "correct_index": row["correct_index"],
                "selected_index": row["selected_index"],
                "explanation": row["explanation"],
            }
            for row in attempt.answers
        ],
    }, 201)


@api_bp.route("/quiz/attempts", methods=["GET"])
@api_auth("awareness.view")
def quiz_attempts():
    query = QuizAttempt.query
    if not g.api_user.can("report.view"):
        query = query.filter(QuizAttempt.user_id == g.api_user.id)
    attempts = query.order_by(QuizAttempt.completed_at.desc()).limit(50).all()
    return ok({"count": len(attempts), "attempts": [a.to_dict() for a in attempts]})


@api_bp.route("/users", methods=["GET"])
@api_auth("user.manage")
def list_users():
    users = User.query.order_by(User.id.asc()).limit(200).all()
    return ok({
        "count": len(users),
        "roles": {role: Role.LABELS[role] for role in Role.ALL},
        "users": [user.to_dict() for user in users],
    })
