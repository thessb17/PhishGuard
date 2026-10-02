"""Email phishing detection interface."""

from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, render_template, request
from flask_login import current_user, login_required

from app.extensions import db, limiter
from app.forms import EmailAnalysisForm
from app.models.audit_log import AuditAction
from app.models.email_analysis import EmailAnalysis
from app.services.detection_trace import build_email_trace
from app.services.email_analyzer import email_analyzer
from app.services.ml_detector import ml_detector
from app.services.risk_engine import risk_engine
from app.utils.audit import log_audit
from app.utils.decorators import capability_required
from app.utils.redaction import safe_excerpt
from app.utils.validators import extract_urls

email_detector_bp = Blueprint("email_detector", __name__)

SAMPLE_PHISHING = {
    "sender": '"Microsoft 365 Security" <alerts@m1crosoft-verify.example>',
    "subject": "URGENT: unusual sign-in detected - verify your account within 24 hours",
    "body": (
        "Dear User,\n\n"
        "Our security team detected an unrecognised sign-in to your Microsoft 365 account "
        "from Kyiv, UA. Your account will be suspended within 24 hours unless you confirm "
        "your identity.\n\n"
        "Please verify your account and confirm your password here:\n"
        "http://m1crosoft-verify.example.secure-login.tk/o365/verify?id=8823ab\n\n"
        "Failure to act will result in permanent loss of access to email and OneDrive.\n\n"
        "Regards,\nIT Helpdesk\nMicrosoft 365 Support Team"
    ),
    "headers": (
        "From: \"Microsoft 365 Security\" <alerts@m1crosoft-verify.example>\n"
        "Reply-To: o365-recovery@mail-support.example\n"
        "Return-Path: <bounce@bulk-sender.example>\n"
        "Authentication-Results: mx.cybersafe.edu; spf=fail smtp.mailfrom=bulk-sender.example; "
        "dkim=none; dmarc=fail header.from=m1crosoft-verify.example\n"
        "X-Mailer: PHPMailer 6.1.7\n"
    ),
}

SAMPLE_LEGITIMATE = {
    "sender": "library-notices@cybersafe.edu",
    "subject": "Your interlibrary loan is ready for collection",
    "body": (
        "Hello Priya,\n\n"
        "The book you requested through interlibrary loan has arrived and is waiting at the "
        "Central Library help desk until 14 March.\n\n"
        "You can review your current loans in the library portal: "
        "https://library.cybersafe.edu/account/loans\n\n"
        "Kind regards,\nCentral Library\nAndhra University"
    ),
    "headers": (
        "From: library-notices@cybersafe.edu\n"
        "Reply-To: library-notices@cybersafe.edu\n"
        "Return-Path: <library-notices@cybersafe.edu>\n"
        "Received: from mx1.cybersafe.edu (mx1.cybersafe.edu [198.51.100.10]) by "
        "mail.cybersafe.edu; Tue, 10 Mar 2026 09:14:02 +0000\n"
        "Received: from lib-app01.cybersafe.edu (lib-app01.cybersafe.edu [198.51.100.44]) by "
        "mx1.cybersafe.edu; Tue, 10 Mar 2026 09:14:01 +0000\n"
        "Authentication-Results: mx.cybersafe.edu; spf=pass smtp.mailfrom=cybersafe.edu; "
        "dkim=pass header.d=cybersafe.edu; dmarc=pass header.from=cybersafe.edu\n"
    ),
}


def _analysis_limit():
    return current_app.config.get("RATELIMIT_ANALYSIS", "60 per minute;600 per hour")


def analyse_email_payload(sender: str, subject: str, body: str, urls: list[str],
                          headers: str, analyst=None, persist: bool = True):
    """Run the hybrid analysis and (optionally) persist the record."""
    rule_result = email_analyzer.analyze(sender=sender, subject=subject, body=body,
                                         urls=urls, headers=headers)
    ml_result = {"available": False}
    worst = rule_result.get("worst_url")
    if worst:
        ml_result = ml_detector.predict(worst["url"])

    notes = []
    if worst and ml_result.get("available"):
        notes.append(
            f"The ML component scored the highest-risk embedded URL ({worst['url'][:70]}); "
            "email bodies themselves are assessed by the rule engine."
        )
    elif not worst:
        notes.append("No URLs were found in the message, so the ML URL model was not applied.")

    risk = risk_engine.combine(
        heuristic_score=rule_result["heuristic_score"],
        ml_score=ml_result.get("risk_score") if ml_result.get("available") else None,
        ml_confidence=ml_result.get("confidence") if ml_result.get("available") else None,
        ml_model=ml_result.get("model") if ml_result.get("available") else None,
        ml_available=bool(ml_result.get("available")),
        extra_notes=notes,
    )

    record = None
    if persist:
        record = EmailAnalysis(
            analyst_id=getattr(analyst, "id", None),
            sender=(rule_result["sender"] or "")[:320],
            reply_to=(rule_result["header_findings"].get("reply_to") or "")[:320],
            subject=safe_excerpt(subject, 500),
            body_excerpt=safe_excerpt(body, 4000),
            body_length=len(body or ""),
            urls=[u["url"] for u in rule_result["urls"]][:20],
            heuristic_score=rule_result["heuristic_score"],
            ml_score=risk.ml_score,
            ml_confidence=risk.ml_confidence,
            final_score=risk.final_score,
            classification=risk.classification,
            indicators=rule_result["indicators"],
            explanation=risk.explanation,
            recommendation=risk.to_dict()["recommendation"],
            header_findings=rule_result["header_findings"],
        )
        db.session.add(record)
        db.session.commit()
    return rule_result, ml_result, risk, record


@email_detector_bp.route("/email-detector", methods=["GET", "POST"])
@login_required
@capability_required("analysis.run")
@limiter.limit(_analysis_limit, methods=["POST"])
def detector():
    form = EmailAnalysisForm()
    sample = request.args.get("sample")
    if request.method == "GET" and sample in {"phishing", "legitimate"}:
        data = SAMPLE_PHISHING if sample == "phishing" else SAMPLE_LEGITIMATE
        form.sender.data = data["sender"]
        form.subject.data = data["subject"]
        form.body.data = data["body"]
        form.headers.data = data["headers"]

    if form.validate_on_submit():
        manual_urls = [
            line.strip() for line in (form.urls.data or "").splitlines() if line.strip()
        ][:20]
        rule_result, ml_result, risk, record = analyse_email_payload(
            sender=form.sender.data or "",
            subject=form.subject.data or "",
            body=form.body.data or "",
            urls=manual_urls,
            headers=form.headers.data or "",
            analyst=current_user,
        )
        log_audit(AuditAction.ANALYSIS_PERFORMED,
                  description=f"Email analysis #{record.id}: {risk.classification} "
                              f"({risk.final_score}/100)",
                  target_type="email_analysis", target_id=record.id,
                  extra={"classification": risk.classification,
                         "heuristic_score": risk.heuristic_score,
                         "ml_score": risk.ml_score,
                         "indicator_count": len([i for i in rule_result["indicators"]
                                                 if i["points"] > 0])})
        return render_template("detectors/email_result.html", result=rule_result,
                               ml=ml_result, risk=risk.to_dict(), record=record,
                               trace=build_email_trace(rule_result, ml_result, risk),
                               detected_urls=extract_urls(form.body.data or ""))

    if form.errors:
        flash("Please provide the message body (at least 10 characters).", "danger")
    recent = (
        EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).limit(8).all()
    )
    return render_template("detectors/email.html", form=form, recent=recent)


@email_detector_bp.route("/email-detector/<int:analysis_id>")
@login_required
@capability_required("analysis.view")
def view_analysis(analysis_id: int):
    record = db.session.get(EmailAnalysis, analysis_id)
    if not record:
        abort(404)
    return render_template("detectors/email_stored.html", record=record)
