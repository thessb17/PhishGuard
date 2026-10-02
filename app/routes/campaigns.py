"""Simulation campaign management."""

from __future__ import annotations

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.forms import CampaignForm, SimpleActionForm
from app.models.audit_log import AuditAction
from app.models.campaign import Campaign, CampaignStatus
from app.services.campaign_service import (
    CampaignError, campaign_stats, create_campaign, demo_participants,
)
from app.services.simulation_templates import TEMPLATES, get_template
from app.utils.audit import log_audit
from app.utils.decorators import capability_required

campaigns_bp = Blueprint("campaigns", __name__)


@campaigns_bp.route("/campaigns")
@login_required
@capability_required("campaign.view")
def list_campaigns():
    page = request.args.get("page", 1, type=int)
    status_filter = (request.args.get("status") or "").upper()
    query = Campaign.query
    if status_filter in CampaignStatus.ALL:
        query = query.filter(Campaign.status == status_filter)
    pagination = query.order_by(Campaign.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    summaries = []
    for campaign in pagination.items:
        stats = campaign_stats(campaign)
        summaries.append({"campaign": campaign, "stats": stats})
    return render_template(
        "campaigns/list.html",
        summaries=summaries,
        pagination=pagination,
        status_filter=status_filter,
        statuses=CampaignStatus.ALL,
        templates=TEMPLATES,
    )


@campaigns_bp.route("/campaigns/create", methods=["GET", "POST"])
@login_required
@capability_required("campaign.create")
def create():
    form = CampaignForm()
    participants = demo_participants()
    form.targets.choices = [
        (user.id, f"{user.full_name} ({user.username}) - {user.department}")
        for user in participants
    ]

    if form.validate_on_submit():
        try:
            campaign = create_campaign(
                name=form.name.data.strip(),
                description=(form.description.data or "").strip(),
                template_key=form.template_key.data,
                difficulty=form.difficulty.data,
                start_date=form.start_date.data,
                end_date=form.end_date.data,
                target_ids=form.targets.data,
                creator=current_user,
                status=form.status.data,
            )
        except CampaignError as exc:
            flash(str(exc), "danger")
            return render_template("campaigns/create.html", form=form,
                                   participants=participants, templates=TEMPLATES), 400

        log_audit(AuditAction.CAMPAIGN_CREATED,
                  description=f"Campaign '{campaign.name}' created with "
                              f"{campaign.participant_count} participants",
                  target_type="campaign", target_id=campaign.id,
                  extra={"template": campaign.template_key, "difficulty": campaign.difficulty,
                         "status": campaign.status})
        flash(f"Campaign '{campaign.name}' created with {campaign.participant_count} "
              f"simulated messages. No credentials are ever collected.", "success")
        return redirect(url_for("campaigns.detail", campaign_id=campaign.id))

    if form.errors:
        flash("Please correct the highlighted fields.", "danger")
    return render_template("campaigns/create.html", form=form,
                           participants=participants, templates=TEMPLATES)


@campaigns_bp.route("/campaigns/<int:campaign_id>")
@login_required
@capability_required("campaign.view")
def detail(campaign_id: int):
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign:
        abort(404)
    stats = campaign_stats(campaign)
    template = get_template(campaign.template_key)
    action_form = SimpleActionForm()
    return render_template("campaigns/detail.html", campaign=campaign, stats=stats,
                           template=template, action_form=action_form,
                           statuses=CampaignStatus.ALL)


@campaigns_bp.route("/campaigns/<int:campaign_id>/status", methods=["POST"])
@login_required
@capability_required("campaign.edit")
def change_status(campaign_id: int):
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign:
        abort(404)
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    new_status = (request.form.get("status") or "").upper()
    if new_status not in CampaignStatus.ALL:
        flash("Unknown campaign status.", "danger")
        return redirect(url_for("campaigns.detail", campaign_id=campaign.id))
    previous = campaign.status
    campaign.status = new_status
    db.session.commit()
    log_audit(AuditAction.CAMPAIGN_UPDATED,
              description=f"Campaign '{campaign.name}' status {previous} -> {new_status}",
              target_type="campaign", target_id=campaign.id,
              extra={"from": previous, "to": new_status})
    flash(f"Campaign status updated to {new_status}.", "success")
    return redirect(url_for("campaigns.detail", campaign_id=campaign.id))


@campaigns_bp.route("/campaigns/<int:campaign_id>/delete", methods=["POST"])
@login_required
@capability_required("campaign.delete")
def delete(campaign_id: int):
    campaign = db.session.get(Campaign, campaign_id)
    if not campaign:
        abort(404)
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    name = campaign.name
    db.session.delete(campaign)
    db.session.commit()
    log_audit(AuditAction.CAMPAIGN_DELETED, description=f"Campaign '{name}' deleted",
              target_type="campaign", target_id=campaign_id)
    flash(f"Campaign '{name}' and its simulation events were deleted.", "info")
    return redirect(url_for("campaigns.list_campaigns"))
