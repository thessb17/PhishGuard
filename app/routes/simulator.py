"""Safe phishing-simulation subsystem.

SAFETY INVARIANTS ENFORCED HERE
-------------------------------
1. The simulated message and the awareness landing page contain **no input
   fields of any kind** - there is nothing to submit and nothing to capture.
2. Only four event types can be recorded: OPENED, LINK_CLICKED,
   TRAINING_PAGE_VIEWED, REPORTED.  Each event stores campaign id, demo user
   reference, simulated message id, event type and timestamp.
3. Simulation links are only reachable by the enrolled participant (or an
   administrator previewing the exercise); the token identifies a message, it
   never authenticates anybody.
4. The blueprint refuses to start if ``SIMULATION_COLLECT_CREDENTIALS`` is
   ever flipped to true - the invariant is asserted at request time.
"""

from __future__ import annotations

from flask import (
    Blueprint, abort, current_app, flash, redirect, render_template, url_for,
)
from flask_login import current_user, login_required

from app.extensions import limiter
from app.forms import SimpleActionForm
from app.models.audit_log import AuditAction
from app.models.campaign import Campaign, CampaignStatus, CampaignTarget
from app.models.simulation import EventType, SimulationEvent
from app.services.campaign_service import awareness_score_for, record_event
from app.services.simulation_templates import TEMPLATES, get_template
from app.utils.audit import log_audit

simulator_bp = Blueprint("simulator", __name__)


@simulator_bp.before_request
def _assert_safety_invariant():
    if current_app.config.get("SIMULATION_COLLECT_CREDENTIALS", False):
        current_app.logger.critical(
            "SIMULATION_COLLECT_CREDENTIALS is enabled - refusing to serve the simulator."
        )
        abort(500)


def _target_or_403(token: str) -> CampaignTarget:
    target = CampaignTarget.query.filter_by(access_token=token).first()
    if not target:
        abort(404)
    if target.user_id != current_user.id and not current_user.is_admin:
        log_audit(AuditAction.ACCESS_DENIED, status="BLOCKED",
                  description="Attempt to open another participant's simulated message",
                  target_type="simulated_message", target_id=target.simulated_message_id)
        abort(403)
    return target


@simulator_bp.route("/simulator")
@login_required
def inbox():
    """The participant's simulated inbox (admins see every enrolment)."""
    query = CampaignTarget.query.join(Campaign)
    if not current_user.is_admin:
        query = query.filter(CampaignTarget.user_id == current_user.id)
    targets = query.order_by(CampaignTarget.created_at.desc()).limit(100).all()

    rows = []
    for target in targets:
        template = get_template(target.campaign.template_key)
        events = SimulationEvent.query.filter_by(
            campaign_id=target.campaign_id, user_id=target.user_id
        ).order_by(SimulationEvent.occurred_at.asc()).all()
        seen = {event.event_type for event in events}
        rows.append({
            "target": target,
            "campaign": target.campaign,
            "template": template,
            "opened": EventType.OPENED in seen,
            "clicked": EventType.LINK_CLICKED in seen,
            "reported": EventType.REPORTED in seen,
            "trained": EventType.TRAINING_PAGE_VIEWED in seen,
            "awareness_score": awareness_score_for(events),
        })
    my_events = (
        SimulationEvent.query.filter_by(user_id=current_user.id)
        .order_by(SimulationEvent.occurred_at.desc()).limit(20).all()
    )
    return render_template("simulator/inbox.html", rows=rows, my_events=my_events,
                           templates=TEMPLATES)


@simulator_bp.route("/simulator/message/<token>")
@login_required
def message(token: str):
    """Render a simulated message and record an OPENED event."""
    target = _target_or_403(token)
    template = get_template(target.campaign.template_key)
    if not template:
        abort(404)
    if target.campaign.status not in (CampaignStatus.ACTIVE, CampaignStatus.COMPLETED):
        flash("This simulation campaign is not active.", "warning")
        return redirect(url_for("simulator.inbox"))

    already = SimulationEvent.query.filter_by(
        campaign_id=target.campaign_id, user_id=target.user_id, event_type=EventType.OPENED
    ).first()
    if not already:
        record_event(target, EventType.OPENED, note="opened in simulated inbox")
        log_audit(AuditAction.SIMULATION_EVENT,
                  description=f"OPENED recorded for {target.simulated_message_id}",
                  target_type="simulated_message", target_id=target.simulated_message_id,
                  extra={"campaign_id": target.campaign_id, "event": EventType.OPENED})

    action_form = SimpleActionForm()
    return render_template("simulator/message.html", target=target, template=template,
                           campaign=target.campaign, action_form=action_form)


@simulator_bp.route("/simulator/click/<token>")
@login_required
@limiter.limit("60 per hour")
def click(token: str):
    """Record LINK_CLICKED and send the participant to the awareness page."""
    target = _target_or_403(token)
    record_event(target, EventType.LINK_CLICKED, note="clicked the simulated link")
    log_audit(AuditAction.SIMULATION_EVENT,
              description=f"LINK_CLICKED recorded for {target.simulated_message_id}",
              target_type="simulated_message", target_id=target.simulated_message_id,
              extra={"campaign_id": target.campaign_id, "event": EventType.LINK_CLICKED})
    return redirect(url_for("simulator.landing", token=token))


@simulator_bp.route("/simulator/landing/<token>")
@login_required
def landing(token: str):
    """Awareness landing page.

    This page teaches; it never asks for anything.  It contains no form, no
    input element and no external resource.
    """
    target = _target_or_403(token)
    template = get_template(target.campaign.template_key)
    if not template:
        abort(404)
    record_event(target, EventType.TRAINING_PAGE_VIEWED, note="viewed awareness landing page")
    log_audit(AuditAction.SIMULATION_EVENT,
              description=f"TRAINING_PAGE_VIEWED recorded for {target.simulated_message_id}",
              target_type="simulated_message", target_id=target.simulated_message_id,
              extra={"campaign_id": target.campaign_id, "event": EventType.TRAINING_PAGE_VIEWED})

    events = SimulationEvent.query.filter_by(
        campaign_id=target.campaign_id, user_id=target.user_id
    ).order_by(SimulationEvent.occurred_at.asc()).all()
    return render_template("simulator/landing.html", target=target, template=template,
                           campaign=target.campaign, events=events,
                           awareness_score=awareness_score_for(events))


@simulator_bp.route("/simulator/report/<token>", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def report_message(token: str):
    """The correct response: report the message as suspicious."""
    target = _target_or_403(token)
    form = SimpleActionForm()
    if not form.validate_on_submit():
        abort(400)
    already = SimulationEvent.query.filter_by(
        campaign_id=target.campaign_id, user_id=target.user_id, event_type=EventType.REPORTED
    ).first()
    if already:
        flash("You have already reported this simulated message.", "info")
        return redirect(url_for("simulator.inbox"))

    record_event(target, EventType.REPORTED, note="reported as phishing by the participant")
    log_audit(AuditAction.SIMULATION_EVENT,
              description=f"REPORTED recorded for {target.simulated_message_id}",
              target_type="simulated_message", target_id=target.simulated_message_id,
              extra={"campaign_id": target.campaign_id, "event": EventType.REPORTED})
    flash("Correct call - you reported a simulated phishing message. "
          "That is exactly the right response.", "success")
    return redirect(url_for("simulator.landing", token=token))


@simulator_bp.route("/simulator/preview/<template_key>")
@login_required
def preview(template_key: str):
    """Template preview for admins/analysts - records no events."""
    if not current_user.can("campaign.view"):
        abort(403)
    template = get_template(template_key)
    if not template:
        abort(404)
    return render_template("simulator/preview.html", template=template)
