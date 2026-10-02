"""URL phishing detection interface."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, render_template, request
from flask_login import current_user, login_required

from app.extensions import db, limiter
from app.forms import URLAnalysisForm
from app.models.audit_log import AuditAction
from app.models.url_analysis import URLAnalysis
from app.services.detection_trace import build_url_trace
from app.services.ml_detector import ml_detector
from app.services.risk_engine import risk_engine
from app.services.url_analyzer import url_analyzer
from app.utils.audit import log_audit
from app.utils.decorators import capability_required
from app.utils.validators import ValidationError, validate_url

url_detector_bp = Blueprint("url_detector", __name__)

SAMPLE_URLS = [
    ("http://198.51.100.23/paypal.com/secure/login.php?cmd=verify-account", "IP-hosted credential page"),
    ("https://cybersafe.edu.verify-student.example/finance/confirm?id=8812", "Subdomain impersonation"),
    ("https://xn--pypal-4ve.com/signin", "Punycode homograph"),
    ("http://bit.ly/3xR4pQz", "Shortened link"),
    ("https://library.cybersafe.edu/account/loans", "Known-good internal URL"),
    ("https://docs.python.org/3/library/json.html?highlight=dumps", "Benign deep-path URL"),
]


def _analysis_limit():
    return current_app.config.get("RATELIMIT_ANALYSIS", "60 per minute;600 per hour")


def analyse_url_payload(url: str, analyst=None, source: str = "web", persist: bool = True):
    """Rule-based + ML analysis fused by the risk engine."""
    rule_result = url_analyzer.analyze(url)
    ml_result = ml_detector.predict(url)
    risk = risk_engine.combine(
        heuristic_score=rule_result["heuristic_score"],
        ml_score=ml_result.get("risk_score") if ml_result.get("available") else None,
        ml_confidence=ml_result.get("confidence") if ml_result.get("available") else None,
        ml_model=ml_result.get("model") if ml_result.get("available") else None,
        ml_available=bool(ml_result.get("available")),
        extra_notes=[rule_result["disclaimer"]],
    )
    record = None
    if persist:
        record = URLAnalysis(
            analyst_id=getattr(analyst, "id", None),
            url=rule_result["url"][:2048],
            normalized_url=rule_result["url"][:2048],
            hostname=rule_result["hostname"][:255],
            scheme=rule_result["scheme"][:16],
            heuristic_score=rule_result["heuristic_score"],
            ml_score=risk.ml_score,
            ml_confidence=risk.ml_confidence,
            ml_model=risk.ml_model,
            final_score=risk.final_score,
            classification=risk.classification,
            indicators=rule_result["indicators"],
            features=rule_result["features"],
            explanation=risk.explanation,
            recommendation=risk.to_dict()["recommendation"],
            source=source,
        )
        db.session.add(record)
        db.session.commit()
    return rule_result, ml_result, risk, record


@url_detector_bp.route("/url-detector", methods=["GET", "POST"])
@login_required
@capability_required("analysis.run")
@limiter.limit(_analysis_limit, methods=["POST"])
def detector():
    form = URLAnalysisForm()
    prefill = request.args.get("url")
    if request.method == "GET" and prefill:
        form.url.data = prefill[:2048]

    if form.validate_on_submit():
        try:
            url = validate_url(form.url.data)
        except ValidationError as exc:
            flash(exc.message, "danger")
            return render_template("detectors/url.html", form=form, samples=SAMPLE_URLS,
                                   recent=_recent(), ml_meta=ml_detector.metadata()), 400

        rule_result, ml_result, risk, record = analyse_url_payload(
            url, analyst=current_user, source="web"
        )
        log_audit(AuditAction.ANALYSIS_PERFORMED,
                  description=f"URL analysis #{record.id}: {risk.classification} "
                              f"({risk.final_score}/100)",
                  target_type="url_analysis", target_id=record.id,
                  extra={"hostname": record.hostname, "classification": risk.classification,
                         "heuristic_score": risk.heuristic_score, "ml_score": risk.ml_score})
        return render_template("detectors/url_result.html", result=rule_result, ml=ml_result,
                               risk=risk.to_dict(), record=record,
                               trace=build_url_trace(rule_result, ml_result, risk),
                               ml_meta=ml_detector.metadata())

    if form.errors:
        flash("Enter a URL to analyse.", "danger")
    return render_template("detectors/url.html", form=form, samples=SAMPLE_URLS,
                           recent=_recent(), ml_meta=ml_detector.metadata())


def _recent():
    return URLAnalysis.query.order_by(URLAnalysis.created_at.desc()).limit(8).all()


@url_detector_bp.route("/url-detector/<int:analysis_id>")
@login_required
@capability_required("analysis.view")
def view_analysis(analysis_id: int):
    record = db.session.get(URLAnalysis, analysis_id)
    if not record:
        abort(404)
    return render_template("detectors/url_stored.html", record=record)
