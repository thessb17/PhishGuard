"""Report generation, viewing and download (CSV / PDF)."""

from __future__ import annotations

import json

from flask import (
    Blueprint, Response, abort, flash, redirect, render_template, request, url_for,
)
from flask_login import current_user, login_required

from app.extensions import db, limiter
from app.forms import SimpleActionForm
from app.models.audit_log import AuditAction
from app.models.campaign import Campaign
from app.models.email_analysis import EmailAnalysis
from app.models.report import Report, ReportType
from app.models.url_analysis import URLAnalysis
from app.services.report_service import (
    create_campaign_report, create_detection_report, pdf_available, report_filename,
    report_to_csv, report_to_pdf,
)
from app.utils.audit import log_audit
from app.utils.decorators import capability_required

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
@capability_required("report.view")
def list_reports():
    page = request.args.get("page", 1, type=int)
    type_filter = (request.args.get("type") or "").upper()
    query = Report.query
    if type_filter in ReportType.ALL:
        query = query.filter(Report.report_type == type_filter)
    pagination = query.order_by(Report.created_at.desc()).paginate(
        page=page, per_page=12, error_out=False
    )
    form = SimpleActionForm()
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(25).all()
    urls = URLAnalysis.query.order_by(URLAnalysis.created_at.desc()).limit(15).all()
    emails = EmailAnalysis.query.order_by(EmailAnalysis.created_at.desc()).limit(15).all()
    return render_template("reports/list.html", pagination=pagination, form=form,
                           campaigns=campaigns, urls=urls, emails=emails,
                           type_filter=type_filter, types=ReportType.ALL,
                           pdf_ok=pdf_available())


@reports_bp.route("/reports/<int:report_id>")
@login_required
@capability_required("report.view")
def detail(report_id: int):
    report = db.session.get(Report, report_id)
    if not report:
        abort(404)
    return render_template("reports/detail.html", report=report, payload=report.payload or {},
                           pdf_ok=pdf_available())


@reports_bp.route("/reports/campaign/<int:campaign_id>", methods=["POST"])
@login_required
@capability_required("report.create")
@limiter.limit("30 per hour")
def generate_campaign_report(campaign_id: int):
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign:
        abort(404)
    report = create_campaign_report(campaign, current_user)
    log_audit(AuditAction.REPORT_GENERATED,
              description=f"Campaign report generated for '{campaign.name}'",
              target_type="report", target_id=report.id,
              extra={"campaign_id": campaign.id, "report_type": report.report_type})
    flash("Campaign report generated.", "success")
    return redirect(url_for("reports.detail", report_id=report.id))


@reports_bp.route("/reports/detection/<string:kind>/<int:analysis_id>", methods=["POST"])
@login_required
@capability_required("report.create")
@limiter.limit("60 per hour")
def generate_detection_report(kind: str, analysis_id: int):
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    kind = kind.lower()
    if kind == "url":
        analysis = db.session.get(URLAnalysis, analysis_id)
    elif kind == "email":
        analysis = db.session.get(EmailAnalysis, analysis_id)
    else:
        abort(404)
    if not analysis:
        abort(404)
    report = create_detection_report(analysis, current_user)
    log_audit(AuditAction.REPORT_GENERATED,
              description=f"{kind.upper()} detection report generated (analysis #{analysis_id})",
              target_type="report", target_id=report.id,
              extra={"kind": kind, "analysis_id": analysis_id})
    flash("Detection report generated.", "success")
    return redirect(url_for("reports.detail", report_id=report.id))


@reports_bp.route("/reports/<int:report_id>/download/<string:fmt>")
@login_required
@capability_required("report.view")
@limiter.limit("60 per hour")
def download(report_id: int, fmt: str):
    report = db.session.get(Report, report_id)
    if not report:
        abort(404)
    fmt = fmt.lower()
    if fmt == "csv":
        payload = report_to_csv(report)
        mimetype, data = "text/csv; charset=utf-8", payload
    elif fmt == "pdf":
        if not pdf_available():
            flash("PDF export requires the 'reportlab' package.", "warning")
            return redirect(url_for("reports.detail", report_id=report.id))
        mimetype, data = "application/pdf", report_to_pdf(report)
    elif fmt == "json":
        # A download is a file, so the raw report document is returned rather
        # than the API envelope used by GET /api/reports/<id>.
        mimetype = "application/json; charset=utf-8"
        data = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    else:
        abort(404)

    log_audit(AuditAction.REPORT_DOWNLOADED,
              description=f"Report #{report.id} exported as {fmt.upper()}",
              target_type="report", target_id=report.id, extra={"format": fmt})
    filename = report_filename(report, fmt)
    return Response(
        data,
        mimetype=mimetype,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
